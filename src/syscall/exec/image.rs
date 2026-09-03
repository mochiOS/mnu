use super::{mapping_error_errno, ExecMeasurement};
use alloc::vec::Vec;

const EM_X86_64: u16 = 0x3e;
const PAGE_SIZE: u64 = 4096;
const USER_ADDRESS_MAX: u64 = 0x0000_7fff_ffff_ffff;
const PF_EXECUTE: u32 = 0x1;
const PF_WRITE: u32 = 0x2;
const PROT_READ_WRITE: u64 = 0x3;
const MAP_PRIVATE_ANONYMOUS: u64 = 0x22;

pub(super) struct ElfImageLayout {
    pub(super) entry: u64,
    pub(super) phdr_vaddr: u64,
    pub(super) phentsize: u64,
    pub(super) phnum: u64,
    pub(super) deferred_zero_regions: Vec<crate::task::MmapRegion>,
}

fn align_page_up(address: u64) -> Option<u64> {
    address
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
}

fn segment_page_range(segment: &crate::elf::Elf64Phdr) -> Option<(u64, u64)> {
    let end = segment.p_vaddr.checked_add(segment.p_memsz)?;
    Some((segment.p_vaddr & !(PAGE_SIZE - 1), align_page_up(end)?))
}

#[inline(never)]
fn deferred_zero_range(
    index: usize,
    segment: &crate::elf::Elf64Phdr,
    segments: &[crate::elf::Elf64Phdr],
) -> Option<(u64, u64)> {
    let writable = segment.p_flags & PF_WRITE != 0;
    let executable = segment.p_flags & PF_EXECUTE != 0;
    if !writable || executable || segment.p_filesz >= segment.p_memsz {
        return None;
    }

    let file_end = segment.p_vaddr.checked_add(segment.p_filesz)?;
    let memory_end = segment.p_vaddr.checked_add(segment.p_memsz)?;
    let start = align_page_up(file_end)?;
    let end = align_page_up(memory_end)?;
    if start >= end {
        return None;
    }

    let overlaps_another_segment = segments.iter().enumerate().any(|(other_index, other)| {
        if other_index == index || other.p_memsz == 0 {
            return false;
        }
        segment_page_range(other)
            .map(|(other_start, other_end)| start < other_end && other_start < end)
            .unwrap_or(true)
    });
    (!overlaps_another_segment).then_some((start, end - start))
}

#[inline(never)]
fn validate_load_segment(data: &[u8], segment: &crate::elf::Elf64Phdr) -> Result<(), u64> {
    use crate::syscall::types::EINVAL;

    if segment.p_memsz < segment.p_filesz || segment.p_vaddr >= USER_ADDRESS_MAX {
        return Err(EINVAL);
    }
    let memory_end = segment.p_vaddr.checked_add(segment.p_memsz).ok_or(EINVAL)?;
    if memory_end > USER_ADDRESS_MAX {
        return Err(EINVAL);
    }
    let source_offset = usize::try_from(segment.p_offset).map_err(|_| EINVAL)?;
    let source_len = usize::try_from(segment.p_filesz).map_err(|_| EINVAL)?;
    source_offset
        .checked_add(source_len)
        .filter(|end| *end <= data.len())
        .ok_or(EINVAL)?;

    let alignment = segment.p_align;
    if alignment > 1
        && (!alignment.is_power_of_two()
            || (segment.p_vaddr.wrapping_sub(segment.p_offset) & (alignment - 1)) != 0)
    {
        return Err(EINVAL);
    }
    if segment.p_flags & (PF_EXECUTE | PF_WRITE) == PF_EXECUTE | PF_WRITE {
        return Err(EINVAL);
    }
    Ok(())
}

#[inline(never)]
fn parse_load_segments(
    data: &[u8],
    measurement: &mut ExecMeasurement,
) -> Result<(crate::elf::Elf64Ehdr, Vec<crate::elf::Elf64Phdr>), u64> {
    use crate::syscall::types::EINVAL;

    let header = measurement
        .parse(|| crate::elf::parse_elf_header(data))
        .filter(|header| header.e_entry != 0)
        .ok_or(EINVAL)?;
    if header.e_machine != EM_X86_64
        || usize::from(header.e_phentsize) < core::mem::size_of::<crate::elf::Elf64Phdr>()
    {
        return Err(EINVAL);
    }

    let header_offset = usize::try_from(header.e_phoff).map_err(|_| EINVAL)?;
    let header_size = usize::from(header.e_phentsize);
    let mut segments = Vec::new();
    for index in 0..usize::from(header.e_phnum) {
        let offset = index
            .checked_mul(header_size)
            .and_then(|value| header_offset.checked_add(value))
            .ok_or(EINVAL)?;
        let program_header = measurement
            .parse(|| crate::elf::parse_phdr(data, offset))
            .ok_or(EINVAL)?;
        if program_header.p_type == crate::elf::PT_LOAD {
            validate_load_segment(data, &program_header)?;
            segments.push(program_header);
        }
    }
    if segments.is_empty() {
        return Err(EINVAL);
    }
    let entry_is_executable = segments.iter().any(|segment| {
        segment.p_flags & PF_EXECUTE != 0
            && segment
                .p_vaddr
                .checked_add(segment.p_memsz)
                .map(|end| header.e_entry >= segment.p_vaddr && header.e_entry < end)
                .unwrap_or(false)
    });
    if !entry_is_executable {
        return Err(EINVAL);
    }
    Ok((header, segments))
}

#[inline(never)]
pub(super) fn map_elf_image(
    data: &[u8],
    table_phys: u64,
    measurement: &mut ExecMeasurement,
) -> Result<ElfImageLayout, u64> {
    use crate::syscall::types::EINVAL;

    let (header, segments) = parse_load_segments(data, measurement)?;
    let load_base = segments[0]
        .p_vaddr
        .checked_sub(segments[0].p_offset)
        .ok_or(EINVAL)?;
    let phdr_vaddr = load_base.checked_add(header.e_phoff).ok_or(EINVAL)?;
    let mut deferred_zero_regions = Vec::new();

    for (index, segment) in segments.iter().enumerate() {
        let source_offset = segment.p_offset as usize;
        let source_end = source_offset + segment.p_filesz as usize;
        let deferred = deferred_zero_range(index, segment, &segments);
        let eager_memory_size = deferred
            .map(|(start, _)| start - segment.p_vaddr)
            .unwrap_or(segment.p_memsz);
        let mapped = measurement.load(|| {
            crate::mem::paging::map_and_copy_segment_to(
                table_phys,
                segment.p_vaddr,
                segment.p_filesz,
                eager_memory_size,
                &data[source_offset..source_end],
                segment.p_flags & PF_WRITE != 0,
                segment.p_flags & PF_EXECUTE != 0,
            )
        });
        mapped.map_err(mapping_error_errno)?;

        if let Some((start, len)) = deferred {
            deferred_zero_regions.push(crate::task::MmapRegion::anonymous(
                start,
                len,
                PROT_READ_WRITE,
                MAP_PRIVATE_ANONYMOUS,
                true,
                false,
            ));
        }
    }

    Ok(ElfImageLayout {
        entry: header.e_entry,
        phdr_vaddr,
        phentsize: u64::from(header.e_phentsize),
        phnum: u64::from(header.e_phnum),
        deferred_zero_regions,
    })
}
