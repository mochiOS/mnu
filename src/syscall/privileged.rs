//! 特権システムコール（物理メモリ系 capability 専用）
//!
//! これらのsyscallは `memory.phys.map` / `memory.phys.translate`
//! capability を持つプロセスだけが呼び出せる。
//! 物理メモリ直接操作、ゼロコピーIO等の実装に使用する。

use super::types::{EFAULT, EINVAL, EPERM};
use crate::capability::Capability;

fn caller_has_phys_translate_capability() -> bool {
    crate::syscall::security::caller_has_any_capability(&[Capability::MemoryPhysTranslate])
        || crate::syscall::security::caller_is_core()
}

fn caller_has_phys_map_capability() -> bool {
    crate::syscall::security::caller_has_any_capability(&[Capability::MemoryPhysMap])
        || crate::syscall::security::caller_is_core()
}

fn caller_can_access_process(pid: crate::task::ProcessId) -> bool {
    crate::syscall::security::caller_can_access_process(pid)
}

fn deallocate_frames(phys_addrs: &[u64]) {
    for &phys in phys_addrs {
        use x86_64::{
            structures::paging::{PhysFrame, Size4KiB},
            PhysAddr,
        };
        if let Some(frame) = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(phys)).ok() {
            let _ = crate::mem::frame::deallocate_frame(frame);
        }
    }
}

fn is_allowed_phys_page(phys_addr: u64) -> bool {
    (phys_addr & 0xfff) == 0 && crate::mem::frame::is_usable_physical_address(phys_addr)
}

fn shared_page_limit() -> u64 {
    crate::mem::frame::get_memory_info()
        .map(|(_, frames)| (frames as u64).max(128))
        .unwrap_or(128)
}

fn map_phys_pages_into_target(
    target_thread_id: u64,
    phys_pages: &[u64],
    virt_addr_hint: u64,
) -> Result<u64, u64> {
    if phys_pages.is_empty() || phys_pages.len() as u64 > shared_page_limit() {
        return Err(EINVAL);
    }
    for &phys_addr in phys_pages {
        if !is_allowed_phys_page(phys_addr) {
            return Err(EINVAL);
        }
    }

    let target_pid = crate::task::thread_to_process_id(target_thread_id).ok_or(EINVAL)?;
    if !caller_can_access_process(target_pid) {
        return Err(EPERM);
    }
    let page_span = (phys_pages.len() as u64)
        .checked_mul(0x1000)
        .ok_or(EINVAL)?;
    let (virt_addr, page_table, reserved_heap_old, reserved_heap_new) = if virt_addr_hint != 0 {
        if virt_addr_hint & 0xfff != 0 {
            return Err(EINVAL);
        }
        let pt = crate::task::with_process(target_pid, |p| p.page_table())
            .flatten()
            .ok_or(EINVAL)?;
        (virt_addr_hint, pt, None, None)
    } else {
        let (virt_addr, pt, old_end, new_end) = crate::task::with_process_mut(target_pid, |p| {
            let base = if p.heap_end() == 0 {
                0x6000_0000_0000u64
            } else {
                p.heap_end()
            };
            let virt_addr = base
                .checked_add(0xfff)
                .map(|v| v & !0xfffu64)
                .ok_or(EINVAL)?;
            let new_end = virt_addr.checked_add(page_span).ok_or(EINVAL)?;
            let pt = p.page_table().ok_or(EINVAL)?;
            let old_end = p.heap_end();
            p.set_heap_end(new_end);
            Ok::<(u64, u64, u64, u64), u64>((virt_addr, pt, old_end, new_end))
        })
        .ok_or(EINVAL)??;
        (virt_addr, pt, Some(old_end), Some(new_end))
    };

    for (i, &phys_addr) in phys_pages.iter().enumerate() {
        let target_virt = virt_addr + (i as u64 * 0x1000);
        if crate::mem::paging::map_page_in_table(page_table, target_virt, phys_addr, true, true)
            .is_err()
        {
            for j in 0..i {
                let rollback_virt = virt_addr + (j as u64 * 0x1000);
                let _ = crate::mem::paging::unmap_page_in_table(page_table, rollback_virt);
            }
            if let (Some(old_end), Some(new_end)) = (reserved_heap_old, reserved_heap_new) {
                let _ = crate::task::with_process_mut(target_pid, |p| {
                    if p.heap_end() == new_end {
                        p.set_heap_end(old_end);
                    }
                });
            }
            return Err(EFAULT);
        }
    }

    Ok(virt_addr)
}

/// 物理ページ配列をターゲットプロセスのアドレス空間にマップ
///
/// # Arguments
/// * arg0: target_thread_id - マップ先のスレッドID
/// * arg1: phys_pages_ptr - 物理ページアドレス配列へのポインタ (u64配列)
/// * arg2: page_count - ページ数
/// * arg3: virt_addr_hint - 仮想アドレスのヒント (0=自動割り当て)
///
/// # Returns
/// 成功時: マップされた仮想アドレス
/// エラー時: 負のエラーコード
pub fn map_physical_pages(
    target_thread_id: u64,
    phys_pages_ptr: u64,
    page_count: u64,
    virt_addr_hint: u64,
) -> u64 {
    if !caller_has_phys_map_capability() {
        return EPERM;
    }

    // パラメータ検証
    if page_count == 0 || page_count > shared_page_limit() {
        return EINVAL;
    }
    if phys_pages_ptr == 0 {
        return EFAULT;
    }

    let mut phys_pages = alloc::vec![0u64; page_count as usize];
    for i in 0..page_count as usize {
        let addr = match phys_pages_ptr.checked_add((i * core::mem::size_of::<u64>()) as u64) {
            Some(addr) => addr,
            None => return EFAULT,
        };
        match super::read_user_u64(addr) {
            Ok(page) => phys_pages[i] = page,
            Err(e) => return e,
        }
    }

    match map_phys_pages_into_target(target_thread_id, &phys_pages, virt_addr_hint) {
        Ok(v) => v,
        Err(e) => e,
    }
}

/// 仮想アドレスから物理アドレスを取得（`memory.phys.translate` 必須）
///
/// # Arguments
/// * arg0: virt_addr - 仮想アドレス
/// * arg1: target_thread_id - 対象スレッドID (0=自プロセス)
///
/// # Returns
/// 成功時: 物理アドレス
/// エラー時: 負のエラーコード
pub fn get_physical_addr(virt_addr: u64, target_thread_id: u64) -> u64 {
    if !caller_has_phys_translate_capability() {
        return EPERM;
    }

    if virt_addr == 0 {
        return EINVAL;
    }

    let pid = if target_thread_id == 0 {
        // 自プロセス
        match crate::task::current_thread_id()
            .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
        {
            Some(pid) => pid,
            None => return EINVAL,
        }
    } else {
        // 指定スレッドのプロセス
        match crate::task::thread_to_process_id(target_thread_id) {
            Some(pid) => pid,
            None => return EINVAL,
        }
    };

    if !caller_can_access_process(pid) {
        return EPERM;
    }

    let page_table = match crate::task::with_process(pid, |p| p.page_table()) {
        Some(Some(pt)) => pt,
        _ => return EINVAL,
    };

    match crate::mem::paging::virt_to_phys_in_table(page_table, virt_addr) {
        Some(phys) => phys,
        None => EFAULT,
    }
}
