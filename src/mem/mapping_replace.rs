//! Replace one ordinary virtual range under the caller's retained VM lock.
use super::{
    mapping_admission, mapping_revocation as transaction, mapping_revocation_native::Native,
    mapping_usage, paging,
};
use crate::task::{MemoryRegion, Process};
use alloc::vec::Vec;
use mnu_abi::status::Error;

/// Prepare all metadata and admission checks before removing any translation.
/// The caller holds PROCESS_TABLE and has validated the new backing authority.
pub(crate) fn replace(
    process: &mut Process,
    region: MemoryRegion,
    byte_ceiling: Option<u64>,
) -> Result<Vec<MemoryRegion>, Error> {
    let start = region.start();
    let end = region.end().ok_or(Error::InvalidArgument)?;
    let length = region.len();
    let table = process.page_table().ok_or(Error::NotReady)?;
    if process.find_dma_buffer_by_addr(start, length).is_some()
        || process.find_mmio_mapping_by_addr(start, length).is_some()
    {
        return Err(Error::AccessDenied);
    }
    mapping_admission::check_unmap(process.memory_regions(), start, end)?;
    let (mut retained, removed) =
        process
            .prepare_remove_memory_range(start, length)
            .map_err(|error| match error {
                crate::task::process::MemoryRangeError::InvalidRange => Error::InvalidArgument,
                crate::task::process::MemoryRangeError::Allocation => Error::ResourceUnavailable,
            })?;
    retained
        .try_reserve(1)
        .map_err(|_| Error::ResourceUnavailable)?;
    retained.push(region);
    if let Some(ceiling) = byte_ceiling.filter(|&value| value != u64::MAX) {
        // Count the proposed metadata union, not old usage + new length. Old
        // PTEs inside the replacement are covered once by the new reservation.
        let projected = mapping_usage::bytes(
            retained
                .iter()
                .map(|region| (region.start(), region.end().unwrap_or(u64::MAX)))
                .chain(
                    process
                        .mmio_mappings()
                        .iter()
                        .map(|mapping| (mapping.virt_start(), mapping.end().unwrap_or(u64::MAX))),
                )
                .chain(
                    process
                        .dma_buffers()
                        .iter()
                        .map(|buffer| (buffer.virt_start(), buffer.end().unwrap_or(u64::MAX))),
                ),
            |start, end| unsafe { paging::next_user_page_entry(table, start, end) },
        )
        .map_err(|_| Error::InvalidAddress)?;
        if projected > ceiling {
            return Err(Error::ResourceUnavailable);
        }
    }
    // SAFETY: the caller retains PROCESS_TABLE across planning, every PTE edit
    // and remote acknowledgement. Faults cannot repopulate suspended entries.
    let mut backend = unsafe { Native::for_process(process, true) };
    transaction::revoke([(table, start, end)], &mut backend).map_err(|error| match error {
        transaction::Error::InvalidRange => Error::InvalidArgument,
        transaction::Error::Allocation => Error::ResourceUnavailable,
        transaction::Error::Backend(error) => error,
    })?;
    // Nothing fallible or allocating remains after old frame references retire.
    process.set_memory_regions(retained);
    Ok(removed)
}
