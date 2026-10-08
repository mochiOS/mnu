//! プロセスグループ・セッション関連のシステムコール

use super::types::{EFAULT, EINVAL, ENOMEM, ESRCH, SUCCESS};

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
            .find_mmap_region(page)
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
            && !process.find_mmap_region(page).is_some_and(|region| {
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
fn record_mmap_protection(
    process: &mut crate::task::Process,
    start: u64,
    end: u64,
    prot: u64,
) -> bool {
    for region in process.mmap_regions_mut() {
        let Some(region_end) = region.end() else {
            return false;
        };
        let overlap_start = start.max(region.start());
        let overlap_end = end.min(region_end);
        if overlap_start < overlap_end
            && !region.set_protection(overlap_start, overlap_end - overlap_start, prot)
        {
            return false;
        }
    }
    true
}

/// mprotect システムコール
///
/// x86_64 の現在のユーザー保護モデルでは READ は常に許可単位になるため、
/// ここでは READ/WRITE/EXEC の組み合わせのうち W+X を拒否しつつ、
/// 既存マッピングの WRITABLE / NX を更新する。
pub fn mprotect(addr: u64, len: u64, prot: u64) -> u64 {
    const PROT_READ: u64 = 0x1;
    const PROT_WRITE: u64 = 0x2;
    const PROT_EXEC: u64 = 0x4;
    const SUPPORTED_MASK: u64 = PROT_READ | PROT_WRITE | PROT_EXEC;
    const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_FFFF;

    if len == 0 {
        return SUCCESS;
    }
    if (prot & !SUPPORTED_MASK) != 0 {
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

    let present = prot != 0;
    let writable = (prot & PROT_WRITE) != 0;
    let executable = (prot & PROT_EXEC) != 0;
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
        protect_memory_pages(
            process,
            table_phys,
            start,
            end,
            present,
            writable,
            executable,
        )?;
        if !record_mmap_protection(process, start, end, prot) {
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
