use core::mem::{size_of, MaybeUninit};
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use mnu_abi::boot::{
    build_reclaimed_memory_map, BootInfo, BootInfoError, MemoryMapTransformError, MemoryRegion,
    MemoryType, PhysicalRange, SmpHandoff, MAX_BOOT_MEMORY_REGIONS,
};

const PAGE_SIZE: u64 = 4096;
const MAX_RESERVED_RANGES: usize = 5;
const RECLAIMED_MEMORY_MAP_CAPACITY: usize =
    MAX_BOOT_MEMORY_REGIONS + MAX_RESERVED_RANGES * 2;
const PREPARATION_UNATTEMPTED: u8 = 0;
const PREPARATION_SUCCEEDED: u8 = 1;
const PREPARATION_FAILED: u8 = 2;

const EMPTY_RANGE: PhysicalRange = PhysicalRange { start: 0, len: 0 };

static mut KERNEL_BOOT_INFO: MaybeUninit<BootInfo> = MaybeUninit::uninit();
static KERNEL_SMP_HANDOFF: SmpHandoff = SmpHandoff::new();
static mut KERNEL_MEMORY_MAP: [MaybeUninit<MemoryRegion>; RECLAIMED_MEMORY_MAP_CAPACITY] =
    [const { MaybeUninit::uninit() }; RECLAIMED_MEMORY_MAP_CAPACITY];
static PREPARATION_STATUS: AtomicU8 = AtomicU8::new(PREPARATION_UNATTEMPTED);
static RECLAIMED_BYTES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootMemoryError {
    InvalidBootInfo(BootInfoError),
    InvalidMemoryMap,
    InvalidKernelRange,
    InvalidSmpHandoff,
    Transform(MemoryMapTransformError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootMemoryPreparation {
    Succeeded { reclaimed_bytes: u64 },
    Failed,
}

fn page_range(start: u64, len: u64) -> Option<PhysicalRange> {
    if len == 0 {
        return None;
    }
    let page_start = start & !(PAGE_SIZE - 1);
    let end = start.checked_add(len)?;
    let page_end = end.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
    Some(PhysicalRange {
        start: page_start,
        len: page_end.checked_sub(page_start)?,
    })
}

fn push_reserved_range(
    ranges: &mut [PhysicalRange; MAX_RESERVED_RANGES],
    len: &mut usize,
    range: Option<PhysicalRange>,
) -> Result<(), BootMemoryError> {
    let Some(range) = range else {
        return Ok(());
    };
    let slot = ranges
        .get_mut(*len)
        .ok_or(BootMemoryError::InvalidMemoryMap)?;
    *slot = range;
    *len += 1;
    Ok(())
}

fn boot_stack_range(
    memory_map: &[MemoryRegion],
    stack_pointer: u64,
) -> Result<Option<PhysicalRange>, BootMemoryError> {
    for region in memory_map {
        let end = region
            .start
            .checked_add(region.len)
            .ok_or(BootMemoryError::InvalidMemoryMap)?;
        if stack_pointer < region.start || stack_pointer >= end {
            continue;
        }
        return match region.region_type {
            MemoryType::BootloaderReclaimable => Ok(Some(PhysicalRange {
                start: region.start,
                len: region.len,
            })),
            MemoryType::Usable => Err(BootMemoryError::InvalidMemoryMap),
            _ => Ok(None),
        };
    }
    Err(BootMemoryError::InvalidMemoryMap)
}

fn copy_smp_handoff(source: &SmpHandoff) {
    KERNEL_SMP_HANDOFF
        .ready
        .store(source.ready.load(Ordering::Relaxed), Ordering::Relaxed);
    KERNEL_SMP_HANDOFF.kernel_secondary_entry.store(
        source.kernel_secondary_entry.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
    KERNEL_SMP_HANDOFF.boot_info_ptr.store(
        source.boot_info_ptr.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
    KERNEL_SMP_HANDOFF.kernel_cr3.store(
        source.kernel_cr3.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
    KERNEL_SMP_HANDOFF.ap_count.store(
        source.ap_count.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
}

fn usable_bytes(memory_map: &[MemoryRegion]) -> u64 {
    memory_map
        .iter()
        .filter(|region| region.region_type == MemoryType::Usable)
        .fold(0u64, |total, region| total.saturating_add(region.len))
}

/// Copies boot-owned metadata into the kernel image and reclaims loader pages that are no
/// longer referenced. The caller must pass the current stack pointer so its UEFI allocation
/// remains reserved until the kernel switches stacks.
///
/// # Safety
///
/// `source` and every address described by it must remain valid for the duration of this call.
/// The function must run once on the BSP before another CPU can observe the copied structures.
pub unsafe fn prepare_boot_info(
    source: *const BootInfo,
    kernel_start: u64,
    kernel_end: u64,
    stack_pointer: u64,
    kernel_heap_addr: u64,
) -> Result<&'static BootInfo, BootMemoryError> {
    let source = source.as_ref().ok_or(BootMemoryError::InvalidMemoryMap)?;
    source
        .validate()
        .map_err(BootMemoryError::InvalidBootInfo)?;
    let memory_map_len = usize::try_from(source.memory_map_len)
        .ok()
        .filter(|len| *len != 0 && *len <= MAX_BOOT_MEMORY_REGIONS)
        .ok_or(BootMemoryError::InvalidMemoryMap)?;
    if source.memory_map_addr == 0 {
        return Err(BootMemoryError::InvalidMemoryMap);
    }
    let source_memory_map = core::slice::from_raw_parts(
        source.memory_map_addr as *const MemoryRegion,
        memory_map_len,
    );

    let kernel_len = kernel_end
        .checked_sub(kernel_start)
        .filter(|len| *len != 0)
        .ok_or(BootMemoryError::InvalidKernelRange)?;
    let mut reserved = [EMPTY_RANGE; MAX_RESERVED_RANGES];
    let mut reserved_len = 0usize;
    push_reserved_range(
        &mut reserved,
        &mut reserved_len,
        page_range(kernel_start, kernel_len),
    )?;
    push_reserved_range(
        &mut reserved,
        &mut reserved_len,
        page_range(source.initfs_addr, source.initfs_size),
    )?;
    push_reserved_range(
        &mut reserved,
        &mut reserved_len,
        page_range(source.rootfs_addr, source.rootfs_size),
    )?;
    push_reserved_range(
        &mut reserved,
        &mut reserved_len,
        page_range(source.smp_trampoline_addr, source.smp_trampoline_size),
    )?;
    push_reserved_range(
        &mut reserved,
        &mut reserved_len,
        boot_stack_range(source_memory_map, stack_pointer)?,
    )?;

    if (source.smp_handoff_addr == 0) != (source.smp_handoff_size == 0) {
        return Err(BootMemoryError::InvalidSmpHandoff);
    }
    if source.smp_handoff_addr != 0 {
        if source.smp_handoff_size as usize != size_of::<SmpHandoff>() {
            return Err(BootMemoryError::InvalidSmpHandoff);
        }
        let source_handoff = (source.smp_handoff_addr as *const SmpHandoff)
            .as_ref()
            .ok_or(BootMemoryError::InvalidSmpHandoff)?;
        copy_smp_handoff(source_handoff);
    }

    let output = core::slice::from_raw_parts_mut(
        core::ptr::addr_of_mut!(KERNEL_MEMORY_MAP).cast::<MemoryRegion>(),
        RECLAIMED_MEMORY_MAP_CAPACITY,
    );
    let output_len = build_reclaimed_memory_map(
        source_memory_map,
        &reserved[..reserved_len],
        output,
    )
    .map_err(BootMemoryError::Transform)?;

    let target = core::ptr::addr_of_mut!(KERNEL_BOOT_INFO).cast::<BootInfo>();
    core::ptr::copy_nonoverlapping(source, target, 1);
    (*target).kernel_heap_addr = kernel_heap_addr;
    (*target).memory_map_addr = output.as_ptr() as u64;
    (*target).memory_map_len = output_len as u64;
    if source.smp_handoff_addr != 0 {
        (*target).smp_handoff_addr = &KERNEL_SMP_HANDOFF as *const SmpHandoff as u64;
    }

    RECLAIMED_BYTES.store(
        usable_bytes(&output[..output_len]).saturating_sub(usable_bytes(source_memory_map)),
        Ordering::Release,
    );
    PREPARATION_STATUS.store(PREPARATION_SUCCEEDED, Ordering::Release);
    Ok(&*target)
}

pub fn note_preparation_failure() {
    PREPARATION_STATUS.store(PREPARATION_FAILED, Ordering::Release);
}

pub fn preparation_status() -> Option<BootMemoryPreparation> {
    match PREPARATION_STATUS.load(Ordering::Acquire) {
        PREPARATION_SUCCEEDED => Some(BootMemoryPreparation::Succeeded {
            reclaimed_bytes: RECLAIMED_BYTES.load(Ordering::Acquire),
        }),
        PREPARATION_FAILED => Some(BootMemoryPreparation::Failed),
        _ => None,
    }
}
