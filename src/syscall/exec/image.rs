use super::{ExecMeasurement, mapping_error_native};
use alloc::vec::Vec;
use mnu_abi::status::Error;

const EM_X86_64: u16 = 0x3e;
const PAGE_SIZE: u64 = 4096;
const USER_EXEC_ADDRESS_MIN: u64 = 0x0040_0000;
const USER_ADDRESS_MAX: u64 = 0x0000_7fff_ffff_ffff;
const PF_EXECUTE: u32 = 0x1;
const PF_WRITE: u32 = 0x2;

pub(super) struct ElfImageLayout {
    pub(super) entry: u64,
    pub(super) phdr_vaddr: u64,
    pub(super) phentsize: u64,
    pub(super) phnum: u64,
    pub(super) deferred_zero_regions: Vec<crate::task::MemoryRegion>,
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
fn validate_load_segment(data: &[u8], segment: &crate::elf::Elf64Phdr) -> Result<(), Error> {
    if segment.p_memsz < segment.p_filesz
        || segment.p_vaddr < USER_EXEC_ADDRESS_MIN
        || segment.p_vaddr >= USER_ADDRESS_MAX
    {
        return Err(Error::InvalidFormat);
    }
    let memory_end = segment
        .p_vaddr
        .checked_add(segment.p_memsz)
        .ok_or(Error::InvalidFormat)?;
    if memory_end > USER_ADDRESS_MAX {
        return Err(Error::InvalidFormat);
    }
    let source_offset = usize::try_from(segment.p_offset).map_err(|_| Error::InvalidFormat)?;
    let source_len = usize::try_from(segment.p_filesz).map_err(|_| Error::InvalidFormat)?;
    source_offset
        .checked_add(source_len)
        .filter(|end| *end <= data.len())
        .ok_or(Error::InvalidFormat)?;

    let alignment = segment.p_align;
    if alignment > 1
        && (!alignment.is_power_of_two()
            || (segment.p_vaddr.wrapping_sub(segment.p_offset) & (alignment - 1)) != 0)
    {
        return Err(Error::InvalidFormat);
    }
    if segment.p_flags & (PF_EXECUTE | PF_WRITE) == PF_EXECUTE | PF_WRITE {
        return Err(Error::InvalidFormat);
    }
    Ok(())
}

#[inline(never)]
fn parse_load_segments(
    data: &[u8],
    measurement: &mut ExecMeasurement,
) -> Result<(crate::elf::Elf64Ehdr, Vec<crate::elf::Elf64Phdr>), Error> {
    let header = measurement
        .parse(|| crate::elf::parse_elf_header(data))
        .filter(|header| header.e_entry != 0)
        .ok_or(Error::InvalidFormat)?;
    if header.e_machine != EM_X86_64
        || usize::from(header.e_phentsize) < core::mem::size_of::<crate::elf::Elf64Phdr>()
    {
        return Err(Error::InvalidFormat);
    }

    let header_offset = usize::try_from(header.e_phoff).map_err(|_| Error::InvalidFormat)?;
    let header_size = usize::from(header.e_phentsize);
    let mut segments = Vec::new();
    for index in 0..usize::from(header.e_phnum) {
        let offset = index
            .checked_mul(header_size)
            .and_then(|value| header_offset.checked_add(value))
            .ok_or(Error::InvalidFormat)?;
        offset
            .checked_add(core::mem::size_of::<crate::elf::Elf64Phdr>())
            .filter(|end| *end <= data.len())
            .ok_or(Error::InvalidFormat)?;
        let program_header = measurement
            .parse(|| crate::elf::parse_phdr(data, offset))
            .ok_or(Error::InvalidFormat)?;
        if program_header.p_type == crate::elf::PT_LOAD {
            validate_load_segment(data, &program_header)?;
            segments
                .try_reserve(1)
                .map_err(|_| Error::ResourceUnavailable)?;
            segments.push(program_header);
        }
    }
    if segments.is_empty() {
        return Err(Error::InvalidFormat);
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
        return Err(Error::InvalidFormat);
    }
    Ok((header, segments))
}

/// Select actual file-backed metadata, or a disjoint read-only copy. Do not
/// infer a readable address from an unmapped file prefix / load bias.
struct ProgramHeaders {
    address: u64,
    copy: Option<core::ops::Range<usize>>,
}

fn program_headers(
    data: &[u8],
    header: &crate::elf::Elf64Ehdr,
    segments: &[crate::elf::Elf64Phdr],
) -> Result<ProgramHeaders, Error> {
    let offset = usize::try_from(header.e_phoff).map_err(|_| Error::InvalidFormat)?;
    let length = usize::from(header.e_phnum)
        .checked_mul(usize::from(header.e_phentsize))
        .filter(|&length| length != 0)
        .ok_or(Error::InvalidFormat)?;
    let end = offset
        .checked_add(length)
        .filter(|&end| end <= data.len())
        .ok_or(Error::InvalidFormat)?;
    let candidate = segments.iter().enumerate().find_map(|(index, segment)| {
        let file_end = segment.p_offset.checked_add(segment.p_filesz)?;
        (header.e_phoff >= segment.p_offset && end as u64 <= file_end)
            .then(|| {
                segment
                    .p_vaddr
                    .checked_add(header.e_phoff - segment.p_offset)
                    .map(|address| (index, address))
            })
            .flatten()
    });
    if let Some((index, address)) = candidate {
        let page_start = address & !(PAGE_SIZE - 1);
        let page_end = align_page_up(
            address
                .checked_add(length as u64)
                .ok_or(Error::InvalidFormat)?,
        )
        .ok_or(Error::InvalidFormat)?;
        // A later LOAD may replace permissions or bytes on a shared page.
        // Keep the exported view independent in that case, too.
        let shared_page = segments.iter().enumerate().any(|(other_index, other)| {
            other_index != index
                && other.p_memsz != 0
                && segment_page_range(other)
                    .map(|(start, end)| page_start < end && start < page_end)
                    .unwrap_or(true)
        });
        if !shared_page {
            return Ok(ProgramHeaders {
                address,
                copy: None,
            });
        }
    }
    let mut first_page = USER_ADDRESS_MAX;
    let mut last_page = 0;
    for segment in segments.iter().filter(|segment| segment.p_memsz != 0) {
        let (start, end) = segment_page_range(segment).ok_or(Error::InvalidFormat)?;
        first_page = first_page.min(start);
        last_page = last_page.max(end);
    }
    let pages = align_page_up(length as u64).ok_or(Error::InvalidFormat)?;
    // Use the same user-image window as LOAD segments. Lower canonical
    // addresses can still contain supervisor mappings in a fresh target root.
    let address = first_page
        .checked_sub(pages)
        .filter(|&address| address >= USER_EXEC_ADDRESS_MIN)
        .or_else(|| {
            last_page
                .checked_add(pages)
                .filter(|&end| end <= USER_ADDRESS_MAX)
                .map(|_| last_page)
        })
        .ok_or(Error::ResourceUnavailable)?;
    Ok(ProgramHeaders {
        address,
        copy: Some(offset..end),
    })
}

#[inline(never)]
pub(super) fn map_elf_image(
    data: &[u8],
    table_phys: u64,
    measurement: &mut ExecMeasurement,
) -> Result<ElfImageLayout, Error> {
    let (header, segments) = parse_load_segments(data, measurement)?;
    let headers = program_headers(data, &header, &segments)?;
    let phdr_vaddr = headers.address;
    let mut deferred_zero_regions = Vec::new();
    // Finish metadata allocation before the first page-table mutation.
    deferred_zero_regions
        .try_reserve_exact(segments.len())
        .map_err(|_| Error::ResourceUnavailable)?;

    if let Some(range) = headers.copy {
        let bytes = &data[range];
        measurement
            .load(|| {
                crate::mem::paging::map_and_copy_segment_to(
                    table_phys,
                    phdr_vaddr,
                    bytes.len() as u64,
                    bytes.len() as u64,
                    bytes,
                    false,
                    false,
                )
            })
            .map_err(mapping_error_native)?;
    }

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
        mapped.map_err(mapping_error_native)?;

        if let Some((start, len)) = deferred {
            deferred_zero_regions.push(crate::task::MemoryRegion::anonymous(
                start,
                len,
                mnu_abi::MEMORY_ACCESS_READ | mnu_abi::MEMORY_ACCESS_WRITE,
                0,
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
