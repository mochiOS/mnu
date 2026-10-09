//! Generic virtual-memory system calls.

use super::types::{EACCES, EFAULT, EINVAL, ENOMEM, ESRCH, SUCCESS};

#[inline]
fn current_pid() -> Option<crate::task::ids::ProcessId> {
    crate::task::current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
}

#[inline(never)]
fn memory_protection_error(error: crate::Kernel) -> u64 {
    match error {
        crate::Kernel::Memory(crate::result::Memory::NotMapped) => EFAULT,
        crate::Kernel::Memory(crate::result::Memory::OutOfMemory) => ENOMEM,
        crate::Kernel::Memory(crate::result::Memory::PermissionDenied)
        | crate::Kernel::Memory(crate::result::Memory::InvalidAddress)
        | crate::Kernel::Memory(crate::result::Memory::AlignmentError)
        | crate::Kernel::InvalidParam => EINVAL,
        _ => EFAULT,
    }
}

#[inline(never)]
fn memory_range_is_mapped(
    process: &crate::task::Process,
    table_phys: u64,
    start: u64,
    end: u64,
) -> bool {
    let mut page = start;
    while page < end {
        let has_page = crate::mem::paging::has_user_page_entry_in_table(table_phys, page);
        let has_region = process
            .find_memory_region(page)
            .and_then(|region| region.end())
            .is_some_and(|region_end| page + 4096 <= region_end);
        if !has_page && !has_region {
            return false;
        }
        page += 4096;
    }
    true
}

#[inline(never)]
fn protect_memory_pages(
    process: &crate::task::Process,
    table_phys: u64,
    start: u64,
    end: u64,
    present: bool,
    writable: bool,
    executable: bool,
) -> Result<(), u64> {
    let mut page = start;
    while page < end {
        let page_writable = writable
            && !process.find_memory_region(page).is_some_and(|region| {
                let page_index = (page - region.start()) / 4096;
                region.is_shared()
                    && region.backing().file_object().is_some()
                    && !region.dirty_pages().contains(&page_index)
            });
        crate::mem::paging::protect_user_page_if_mapped(
            table_phys,
            page,
            present,
            page_writable,
            executable,
        )
        .map_err(memory_protection_error)?;
        page += 4096;
    }
    Ok(())
}

#[inline(never)]
fn record_mapping_access(
    process: &mut crate::task::Process,
    start: u64,
    end: u64,
    access: u64,
) -> bool {
    for region in process.memory_regions_mut() {
        let Some(region_end) = region.end() else {
            return false;
        };
        let overlap_start = start.max(region.start());
        let overlap_end = end.min(region_end);
        if overlap_start < overlap_end
            && !region.set_access(overlap_start, overlap_end - overlap_start, access)
        {
            return false;
        }
    }
    true
}

/// Changes the native access permissions of an existing user mapping.
///
/// The kernel accepts only the generic `MEMORY_ACCESS_*` ABI. It deliberately
/// knows nothing about POSIX `mprotect`, `PROT_*`, or their error conventions.
pub fn protect(addr: u64, len: u64, access: u64) -> u64 {
    const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_FFFF;

    if len == 0 {
        return SUCCESS;
    }
    if (access & !mnu_abi::MEMORY_ACCESS_ALL) != 0 {
        return EINVAL;
    }
    if addr == 0 || addr > USER_SPACE_END {
        return EINVAL;
    }

    let end_inclusive = match addr.checked_add(len.saturating_sub(1)) {
        Some(v) if v <= USER_SPACE_END => v,
        _ => return EINVAL,
    };
    let start = addr & !0xfffu64;
    let length = match (end_inclusive & !0xfffu64)
        .checked_add(4096)
        .and_then(|end| end.checked_sub(start))
    {
        Some(v) if v != 0 => v,
        _ => return EINVAL,
    };

    let present = access != 0;
    let writable = (access & mnu_abi::MEMORY_ACCESS_WRITE) != 0;
    let executable = (access & mnu_abi::MEMORY_ACCESS_EXECUTE) != 0;
    if present && writable && executable {
        return EINVAL;
    }

    let pid = match current_pid() {
        Some(p) => p,
        None => return ESRCH,
    };
    let end = start + length;
    let result = crate::task::with_process_mut(pid, |process| {
        let table_phys = process.page_table().ok_or(EINVAL)?;
        if !memory_range_is_mapped(process, table_phys, start, end) {
            return Err(EFAULT);
        }
        // Validate the entire range before changing any page permissions.
        // A mapping retains the authority of its original backing handle even
        // after that handle is closed or transferred with fewer rights.
        for region in process.memory_regions() {
            let region_end = region.end().ok_or(EFAULT)?;
            if start < region_end && end > region.start() && !region.permits_access(access) {
                return Err(EACCES);
            }
        }
        protect_memory_pages(
            process, table_phys, start, end, present, writable, executable,
        )?;
        if !record_mapping_access(process, start, end, access) {
            return Err(EFAULT);
        }
        Ok(())
    });
    match result {
        Some(Ok(())) => SUCCESS,
        Some(Err(errno)) => errno,
        None => ESRCH,
    }
}
