//! Preflight a complete virtual range before changing PTEs or mapping metadata.
//! The caller holds the mapping/process lock until its edit is committed;
//! backing reservations start under that same lock. No allocation or IPC.
pub(crate) fn check(
    regions: &[crate::task::MemoryRegion],
    start: u64,
    end: u64,
) -> Result<(), u64> {
    if start >= end {
        return Err(crate::syscall::EINVAL);
    }
    for region in regions {
        let region_end = region.end().ok_or(crate::syscall::EINVAL)?;
        if start < region_end && region.start() < end {
            if let Some(object) = region.backing().file_object() {
                object.with_memory_generation(object.memory_generation(), || Ok(()))?;
            }
        }
    }
    Ok(())
}
