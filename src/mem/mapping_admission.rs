//! Preflight a complete virtual range before changing PTEs or mapping metadata.
//! The caller holds the mapping/process lock until its edit is committed;
//! backing reservations start under that same lock. No allocation or IPC.
pub(crate) fn check(
    regions: &[crate::task::MemoryRegion],
    start: u64,
    end: u64,
) -> Result<(), u64> {
    check_range(regions, start, end, false)
}

/// Unmapping can discard unavailable data, but not an extent owner's PTEs.
/// This admission must never be used for protection changes or data access.
pub(crate) fn check_unmap(
    regions: &[crate::task::MemoryRegion],
    start: u64,
    end: u64,
) -> Result<(), u64> {
    check_range(regions, start, end, true)
}

fn check_range(
    regions: &[crate::task::MemoryRegion],
    start: u64,
    end: u64,
    removing: bool,
) -> Result<(), u64> {
    if start >= end {
        return Err(crate::syscall::EINVAL);
    }
    for region in regions {
        let region_end = region.end().ok_or(crate::syscall::EINVAL)?;
        if start < region_end && region.start() < end {
            if let Some(object) = region.backing().file_object() {
                if removing {
                    object.check_mapping_removal()?;
                } else {
                    object.with_memory_generation(object.memory_generation(), || Ok(()))?;
                }
            }
        }
    }
    Ok(())
}

/// Resident kernel accesses use a typed transient condition, not a user fault.
pub(crate) fn check_access(
    regions: &[crate::task::MemoryRegion],
    start: u64,
    length: u64,
) -> crate::result::Result<()> {
    use crate::{Kernel, result::Memory};
    if length == 0 {
        return Ok(());
    }
    let end = start
        .checked_add(length)
        .ok_or(Kernel::Memory(Memory::InvalidAddress))?;
    check(regions, start, end).map_err(|error| {
        Kernel::Memory(if error == crate::syscall::EAGAIN {
            Memory::Busy
        } else {
            Memory::InvalidAddress
        })
    })
}
