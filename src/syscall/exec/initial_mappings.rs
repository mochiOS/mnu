//! Preparation in a private target root, never a mutation of the caller's VM.
use crate::syscall::types::{EACCES, EINVAL, ENOMEM};
use crate::task::{HandleRights, KernelObject, MemoryRegion};
use alloc::vec::Vec;

pub(super) fn prepare(
    table: u64,
    startup: mnu_abi::process_image::StartupImage<'_>,
    regions: &mut Vec<MemoryRegion>,
) -> Result<(), u64> {
    regions
        .try_reserve_exact(startup.mappings().count())
        .map_err(|_| ENOMEM)?;
    for mapping in startup.mappings() {
        let end = mapping.address.checked_add(mapping.length).ok_or(EINVAL)?;
        if crate::mem::paging::is_user_range_occupied_in_table(
            table,
            mapping.address,
            mapping.length,
        ) || regions.iter().any(|region| {
            region
                .end()
                .is_none_or(|other_end| mapping.address < other_end && region.start() < end)
        }) {
            return Err(EINVAL);
        }
        let writable = mapping.access & mnu_abi::MEMORY_ACCESS_WRITE != 0;
        let shared = mapping.options & mnu_abi::MEMORY_MAP_SHARED != 0;
        let region = if mapping.backing_handle == 0 {
            MemoryRegion::anonymous(
                mapping.address,
                mapping.length,
                mapping.access,
                mapping.options,
                writable,
                shared,
            )
        } else {
            let mut required = HandleRights::MAP.union(HandleRights::READ);
            if shared && writable {
                required = required.union(HandleRights::WRITE);
            }
            let (object, rights) =
                crate::syscall::handle::object_with_rights(mapping.backing_handle, required)?;
            let KernelObject::VmObject(object) = object else {
                return Err(EINVAL);
            };
            let extent = object.memory_length().ok_or(EINVAL)?;
            if mapping
                .backing_offset
                .checked_add(mapping.length)
                .is_none_or(|end| end > extent)
            {
                return Err(EINVAL);
            }
            // Match MemoryMap: private RAM may be copied writable, but cannot
            // become executable. Read-only shared authority cannot be raised
            // later by MemoryProtect, even if the source Handle is closed.
            let mut maximum = mnu_abi::MEMORY_ACCESS_ALL & !mnu_abi::MEMORY_ACCESS_EXECUTE;
            if shared && !rights.contains(HandleRights::WRITE) {
                maximum &= !mnu_abi::MEMORY_ACCESS_WRITE;
            }
            if mapping.access & !maximum != 0 {
                return Err(EACCES);
            }
            MemoryRegion::file_backed(
                mapping.address,
                mapping.length,
                mapping.access,
                mapping.options,
                object,
                mapping.backing_offset,
                writable,
                shared,
                maximum,
            )
        };
        regions.push(region);
    }
    Ok(())
}
