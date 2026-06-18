//! プロセス管理関連のシステムコール

use super::types::{EFAULT, EINVAL, EIO, ENOMEM, ENOSYS, EPERM, SUCCESS};
use crate::interrupt::spinlock::SpinLock;
use crate::task::ThreadId;
use alloc::string::ToString;
use alloc::vec::Vec;

fn caller_has_process_inspect_capability() -> bool {
    crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessInspect,
    ])
}

fn caller_has_process_spawn_capability() -> bool {
    crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessSpawn,
    ])
}

/// ユーザー空間の上限アドレス (x86-64 canonical hole 下側)
const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_FFFF;
/// Linux互換: 子プロセスが存在しない
const ECHILD: u64 = (-10i64) as u64;
/// Linux互換: 操作がタイムアウトした
const ETIMEDOUT: u64 = (-110i64) as u64;
use crate::task::{current_thread_id, exit_current_task};

#[derive(Clone, Copy)]
struct FutexWaitEntry {
    tid: ThreadId,
    uaddr: u64,
    wake_tick: u64,
}

const MAX_FUTEX_WAITERS: usize = crate::task::ThreadQueue::MAX_THREADS;
const NO_TIMEOUT_WAKE_TICK: u64 = u64::MAX;
static FUTEX_WAIT_QUEUE: SpinLock<[Option<FutexWaitEntry>; MAX_FUTEX_WAITERS]> =
    SpinLock::new([None; MAX_FUTEX_WAITERS]);

#[inline]
fn aslr_mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

fn randomized_heap_base(pid: crate::task::ProcessId, floor: u64, max_pages: u64) -> u64 {
    let seed = crate::cpu::boot_entropy_u64()
        ^ crate::interrupt::timer::get_ticks().rotate_left(17)
        ^ pid.as_u64().rotate_left(9)
        ^ floor.rotate_left(3);
    floor.saturating_add((aslr_mix64(seed) % max_pages) * 4096)
}

#[inline]
fn page_align_up(addr: u64) -> Option<u64> {
    addr.checked_add(4095).map(|v| v & !4095)
}

#[inline]
fn is_user_range(addr: u64, len: u64) -> bool {
    if len == 0 {
        return addr <= USER_SPACE_END;
    }
    let end = match addr.checked_add(len.saturating_sub(1)) {
        Some(e) => e,
        None => return false,
    };
    addr <= USER_SPACE_END && end <= USER_SPACE_END
}

const MEMORY_SYNC_CHUNK_BYTES: usize = 4096;

fn writeback_shared_mmap_region(
    region: &mut crate::task::MmapRegion,
    sync_start: u64,
    data: &[u8],
) -> u64 {
    if data.is_empty() {
        return SUCCESS;
    }
    if !region.is_shared() || !region.is_writable() {
        return EINVAL;
    }

    let Some(region_end) = region.end() else {
        return EINVAL;
    };
    let Some(sync_end) = sync_start.checked_add(data.len() as u64) else {
        return EINVAL;
    };
    if sync_start < region.start() || sync_end > region_end {
        return EINVAL;
    }

    let backing_base = sync_start - region.start();
    let mut offset = 0usize;

    while offset < data.len() {
        let chunk_len = core::cmp::min(MEMORY_SYNC_CHUNK_BYTES, data.len() - offset);
        let write_off = match backing_base.checked_add(offset as u64) {
            Some(v) => v,
            None => return EINVAL,
        };
        let backing = region.backing_mut().file_data_mut();
        let end = match (write_off as usize).checked_add(chunk_len) {
            Some(v) => v,
            None => return EINVAL,
        };
        if end > backing.len() {
            backing.resize(end, 0);
        }
        backing[write_off as usize..end].copy_from_slice(&data[offset..offset + chunk_len]);

        offset += chunk_len;
    }

    let _ = region.take_dirty_pages();
    SUCCESS
}

fn register_futex_waiter(tid: ThreadId, uaddr: u64, wake_tick: u64) -> bool {
    let mut queue = FUTEX_WAIT_QUEUE.lock();

    for slot in queue.iter_mut() {
        if slot.is_some_and(|entry| entry.tid == tid) {
            // 1スレッドは同時に1つの futex wait のみ許可する
            return false;
        }
    }

    for slot in queue.iter_mut() {
        if slot.is_none() {
            *slot = Some(FutexWaitEntry {
                tid,
                uaddr,
                wake_tick,
            });
            return true;
        }
    }

    false
}

fn futex_waiter_exists(tid: ThreadId, uaddr: u64) -> bool {
    let queue = FUTEX_WAIT_QUEUE.lock();
    queue
        .iter()
        .flatten()
        .any(|entry| entry.tid == tid && entry.uaddr == uaddr)
}

fn remove_futex_waiter_by_tid(tid: ThreadId) -> bool {
    let mut queue = FUTEX_WAIT_QUEUE.lock();
    for slot in queue.iter_mut() {
        if slot.is_some_and(|entry| entry.tid == tid) {
            *slot = None;
            return true;
        }
    }
    false
}

pub fn clear_futex_waiter(tid: ThreadId) {
    let _ = remove_futex_waiter_by_tid(tid);
}

/// FUTEX_WAIT のタイムアウトに達したスレッドを起床させる（タイマー割り込みから呼ばれる）
pub fn wake_due_futex_waiters(now_tick: u64) {
    let mut wake_list = [None; MAX_FUTEX_WAITERS];
    let mut wake_count = 0usize;

    {
        let mut queue = FUTEX_WAIT_QUEUE.lock();
        for slot in queue.iter_mut() {
            if let Some(entry) = *slot {
                if entry.wake_tick != NO_TIMEOUT_WAKE_TICK && now_tick >= entry.wake_tick {
                    *slot = None;
                    if wake_count < wake_list.len() {
                        wake_list[wake_count] = Some(entry.tid);
                        wake_count += 1;
                    } else {
                        crate::audit::log(
                            crate::audit::AuditEventKind::Fault,
                            "futex wake list overflow; dropping excess wake event",
                        );
                    }
                }
            }
        }
    }

    for tid in wake_list.iter().take(wake_count).flatten() {
        crate::task::with_thread_mut(*tid, |thread| thread.set_futex_timed_out(true));
        crate::task::wake_thread(*tid);
    }
}

/// Exitシステムコール
///
/// プロセスを終了する
///
/// # 引数
/// - `exit_code`: 終了コード
///
/// # 戻り値
/// このシステムコールは戻らない（プロセスが終了する）
pub fn exit(exit_code: u64) -> ! {
    crate::sprintln!("Process exiting with code: {}", exit_code);

    // スケジューラから現在のタスクを削除して終了
    exit_current_task(exit_code)
}

/// List processes into a user-supplied buffer.
/// arg0 = user buffer ptr, arg1 = buffer length in bytes.
pub fn list_processes(buf_ptr: u64, buf_len: u64) -> u64 {
    use crate::task::ProcessState;

    if !caller_has_process_inspect_capability() {
        return EPERM;
    }

    const RECORD_SIZE: usize = 88;
    if buf_ptr == 0 {
        return 0;
    }
    let max_bytes = buf_len as usize;
    let max_entries = max_bytes / RECORD_SIZE;
    if max_entries == 0 {
        return 0;
    }

    let mut records: Vec<[u8; RECORD_SIZE]> = Vec::new();
    crate::task::for_each_process(|proc| {
        if records.len() >= max_entries {
            return;
        }

        let mut out_buf = [0u8; RECORD_SIZE];
        // tid and pid: use process id for both (no separate thread id here)
        let pid_u = proc.id().as_u64();
        out_buf[0..8].copy_from_slice(&pid_u.to_ne_bytes());
        out_buf[8..16].copy_from_slice(&pid_u.to_ne_bytes());
        // state mapping
        let state_num: u64 = match proc.state() {
            ProcessState::Running => 1,
            ProcessState::Sleeping => 3,
            ProcessState::Zombie => 4,
            ProcessState::Terminated => 4,
            _ => 0,
        };
        out_buf[16..24].copy_from_slice(&state_num.to_ne_bytes());
        // name at offset 32, max 64 bytes
        let name = proc.name();
        let name_bytes = name.as_bytes();
        let copy_len = core::cmp::min(64, name_bytes.len());
        out_buf[32..32 + copy_len].copy_from_slice(&name_bytes[..copy_len]);
        records.push(out_buf);
    });

    let mut written = 0usize;
    while written < records.len() {
        let dest_ptr = buf_ptr + (written * RECORD_SIZE) as u64;
        if let Err(_) = super::copy_to_user(dest_ptr, &records[written]) {
            break;
        }
        written += 1;
    }

    written as u64
}

/// GetPidシステムコール
///
/// 現在のプロセスIDを取得する
///
/// # 戻り値
/// プロセスID
pub fn getpid() -> u64 {
    if let Some(tid) = current_thread_id() {
        crate::task::with_thread(tid, |thread| thread.process_id().as_u64()).unwrap_or(0)
    } else {
        0
    }
}

/// GetTidシステムコール
///
/// 現在のスレッドIDを取得する
///
/// # 戻り値
/// スレッドID
pub fn gettid() -> u64 {
    if let Some(tid) = current_thread_id() {
        tid.as_u64()
    } else {
        0
    }
}

/// Brkシステムコール
///
/// メモリのヒープ領域サイズを変更する
pub fn brk(addr: u64) -> u64 {
    // 現在のプロセスIDを取得
    let current_tid = match current_thread_id() {
        Some(tid) => tid,
        None => return ENOSYS,
    };

    // プロセスIDを取得
    let pid = match crate::task::with_thread(current_tid, |t| t.process_id()) {
        Some(pid) => pid,
        None => return ENOSYS,
    };

    let result = crate::task::with_process_mut(pid, |process| {
        crate::debug!(
            "brk(pid={:?}, process='{}'): req={:#x}, heap_start={:#x}, heap_end={:#x}",
            pid,
            process.name(),
            addr,
            process.heap_start(),
            process.heap_end()
        );
        if process.heap_start() == 0 {
            let exec_cfg = crate::config::kernel().exec;
            let default_heap_base = randomized_heap_base(
                pid,
                exec_cfg.brk_heap_base_min,
                exec_cfg.brk_heap_aslr_max_pages,
            );
            process.set_heap_start(default_heap_base);
            process.set_heap_end(default_heap_base);
        }
        // addr == 0 なら現在の位置を返す
        if addr == 0 {
            return Ok(process.heap_end());
        }

        if addr < process.heap_start() {
            return Err(EINVAL);
        }

        let current_brk = process.heap_end();

        // ユーザー空間の上限アドレスを超えるbrkを拒否
        if !is_user_range(addr, 1) {
            return Err(EINVAL);
        }

        // 縮小または変化なし
        if addr <= current_brk {
            process.set_heap_end(addr);
            return Ok(addr);
        }

        // プロセス固有のページテーブルアドレスを取得
        let pt_phys = match process.page_table() {
            Some(p) => p,
            None => return Err(ENOSYS),
        };

        // 拡大時にページをプロセスのページテーブルにマップ（書き込み可能、実行不可）
        // 既存のヒープページを上書きしないよう、未マップ開始位置から拡張する。
        let start_addr =
            if crate::mem::paging::is_user_range_mapped_in_table(pt_phys, current_brk, 1) {
                current_brk.saturating_add(1)
            } else {
                current_brk
            };
        let start_page = match page_align_up(start_addr) {
            Some(v) => v,
            None => return Err(EINVAL),
        };
        // 一部のユーザーランタイムは brk 境界アドレスにメタデータを書き込むため、
        // `addr` がページ境界ちょうどの場合でもそのページを含めて確保する。
        let map_end = addr.saturating_add(1);
        let end_page = match page_align_up(map_end) {
            Some(v) if is_user_range(v.saturating_sub(1), 1) => v,
            _ => return Err(EINVAL),
        };

        if end_page > start_page {
            let size = end_page - start_page;
            if crate::mem::paging::map_and_copy_segment_to(
                pt_phys,
                start_page,
                0,
                size,
                &[],
                true,
                false,
            )
            .is_err()
            {
                return Err(ENOSYS);
            }
        }

        process.set_heap_end(addr);
        Ok(addr)
    });

    match result {
        Some(Ok(addr)) => {
            crate::debug!("brk(pid={:?}) -> {:#x}", pid, addr);
            addr
        }
        Some(Err(err)) => {
            crate::debug!("brk(pid={:?}) -> err {:#x}", pid, err);
            err
        }
        None => {
            crate::debug!("brk(pid={:?}) -> ENOSYS", pid);
            ENOSYS
        }
    }
}

/// Forkシステムコール
///
/// プロセスを複製する
pub fn fork() -> u64 {
    if !caller_has_process_spawn_capability() {
        return crate::syscall::EPERM;
    }

    let parent_tid = match current_thread_id() {
        Some(tid) => tid,
        None => return ENOSYS,
    };
    let parent_pid = match crate::task::with_thread(parent_tid, |t| t.process_id()) {
        Some(pid) => pid,
        None => return ENOSYS,
    };

    let (
        parent_priv,
        parent_priority,
        parent_foreground,
        parent_pt,
        heap_start,
        heap_end,
        stack_bottom,
        stack_top,
        parent_mmap_regions,
    ) = match crate::task::with_process(parent_pid, |p| {
        (
            p.privilege(),
            p.priority(),
            p.is_foreground(),
            p.page_table(),
            p.heap_start(),
            p.heap_end(),
            p.stack_bottom(),
            p.stack_top(),
            p.clone_mmap_regions_for_fork(),
        )
    }) {
        Some(v) => v,
        None => return ENOSYS,
    };
    let parent_pt = match parent_pt {
        Some(pt) => pt,
        None => return ENOSYS,
    };

    let child_pt = match crate::mem::paging::clone_user_page_table(parent_pt) {
        Ok(pt) => pt,
        Err(err) => {
            crate::warn!("fork: clone_user_page_table failed: {:?}", err);
            return ENOMEM;
        }
    };

    let (user_rip, user_rsp, user_rflags, parent_fs) = crate::task::with_thread(parent_tid, |t| {
        let (rip, rsp, rflags) = t.syscall_user_context();
        (rip, rsp, rflags, t.fs_base())
    })
    .unwrap_or((0, 0, 0, 0));
    if user_rip == 0 || user_rsp == 0 {
        let _ = crate::mem::paging::destroy_user_page_table(child_pt);
        return ENOSYS;
    }

    // 親プロセスの FD テーブルを fork 前にクローンする
    let child_fd_table = crate::task::with_process(parent_pid, |p| p.clone_fd_table_for_fork());

    let mut child_proc =
        crate::task::Process::new("fork", parent_priv, Some(parent_pid), parent_priority);
    child_proc.set_foreground(parent_foreground);
    child_proc.set_page_table(child_pt);
    child_proc.set_heap_start(heap_start);
    child_proc.set_heap_end(heap_end);
    child_proc.set_stack_bottom(stack_bottom);
    child_proc.set_stack_top(stack_top);
    child_proc.set_mmap_regions(parent_mmap_regions);
    crate::debug!(
        "[STACK_INIT] FORK child: stack_bottom={:#x}, stack_top={:#x}",
        stack_bottom,
        stack_top
    );
    // 親の FD テーブルを子に継承する
    if let Some(table) = child_fd_table {
        child_proc.set_fd_table(table);
    }
    let child_pid = child_proc.id();
    if crate::task::add_process(child_proc).is_none() {
        let _ = crate::mem::paging::destroy_user_page_table(child_pt);
        return ENOMEM;
    }

    let kstack_size = crate::config::kernel().exec.kernel_thread_stack_size;
    let kstack = match crate::task::thread::allocate_kernel_stack(kstack_size) {
        Some(s) => s,
        None => {
            let _ = crate::task::remove_process(child_pid);
            let _ = crate::mem::paging::destroy_user_page_table(child_pt);
            return ENOMEM;
        }
    };
    let child_thread = crate::task::Thread::new_fork_child(
        child_pid,
        user_rip,
        user_rsp,
        user_rflags,
        parent_fs,
        kstack,
        kstack_size,
    );
    if crate::task::add_thread(child_thread).is_none() {
        let _ = crate::task::remove_process(child_pid);
        let _ = crate::mem::paging::destroy_user_page_table(child_pt);
        return ENOMEM;
    }

    child_pid.as_u64()
}

/// Spawnシステムコール
///
/// 現状は `fork()` と同じく現在のプロセスを複製する最小実装。
/// flags/reserved は将来のプロセス生成オプション用に確保してある。
pub fn spawn(flags: u64, reserved: u64) -> u64 {
    let _ = (flags, reserved);
    fork()
}

/// Sleepシステムコール
///
/// 指定されたミリ秒数の間スリープする
///
/// # 引数
/// - `milliseconds`: スリープ時間（ミリ秒）
///
/// # 戻り値
/// 成功時はSUCCESS
pub fn sleep(milliseconds: u64) -> u64 {
    if milliseconds == 0 {
        // sleep(0) は待機せず、協調的に実行権を譲る
        crate::task::yield_now();
        return SUCCESS;
    }
    let wait_ticks = crate::interrupt::timer::ms_to_ticks_ceil(milliseconds);
    let target = crate::syscall::time::get_ticks().saturating_add(wait_ticks);
    crate::syscall::time::sleep_until(target);
    SUCCESS
}

/// Waitシステムコール (wait4)
///
/// # 引数
/// - `pid`: 待機するプロセスID (-1 = 任意の子プロセス)
/// - `status_ptr`: 終了ステータスを書き込むポインタ (0 = 無視)
/// - `options`: WNOHANG(0x1) = ノンブロッキング
pub fn wait(_pid: u64, status_ptr: u64, options: u64) -> u64 {
    const WNOHANG: u64 = 0x1;
    let pid = _pid as i64;
    if options & !WNOHANG != 0 {
        return EINVAL;
    }
    if pid < -1 || pid == 0 {
        return EINVAL;
    }

    if status_ptr != 0 && !super::validate_user_ptr(status_ptr, 4) {
        return EFAULT;
    }

    // 呼び出し元プロセス
    let current_pid = match current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
    {
        Some(pid) => pid,
        None => return ECHILD,
    };

    let target_pid = if pid == -1 {
        None
    } else {
        Some(crate::task::ProcessId::from_u64(pid as u64))
    };

    // POSIX互換の待機: ゾンビを回収、存在しなければブロックまたはWNOHANGで0
    loop {
        if let Some((reaped_pid, exit_code)) =
            crate::task::reap_zombie_child_process(current_pid, target_pid)
        {
            if status_ptr != 0 {
                let status = ((exit_code & 0xff) << 8) as i32;
                if crate::syscall::write_user_i32(status_ptr, status).is_err() {
                    return EFAULT;
                }
            }
            return reaped_pid.as_u64();
        }

        if !crate::task::has_child_process(current_pid, target_pid) {
            return ECHILD;
        }

        if options & WNOHANG != 0 {
            return 0;
        }

        crate::task::yield_now();
    }
}

/// page fault を契機に file-backed mmap を 1 ページだけ解決する。
pub fn handle_user_mmap_fault(fault_addr: u64, is_write: bool) -> bool {
    let tid = match current_thread_id() {
        Some(t) => t,
        None => return false,
    };
    let pid = match crate::task::with_thread(tid, |t| t.process_id()) {
        Some(p) => p,
        None => return false,
    };

    let page_addr = fault_addr & !4095;
    crate::debug!(
        "[MMAP_FAULT] addr={:#x} page={:#x} write={}",
        fault_addr,
        page_addr,
        is_write
    );
    let result = crate::task::with_process_mut(pid, |process| {
        let pt_phys = match process.page_table() {
            Some(p) => p,
            None => return Err(EINVAL),
        };
        let region = match process.find_mmap_region_mut(fault_addr) {
            Some(region) => region,
            None => {
                crate::debug!("[MMAP_FAULT] no region for {:#x}", fault_addr);
                return Err(EINVAL);
            }
        };
        crate::debug!(
            "[MMAP_FAULT] region start={:#x} len={:#x} writable={} shared={}",
            region.start(),
            region.len(),
            region.is_writable(),
            region.is_shared()
        );
        if is_write && !region.is_writable() {
            crate::debug!("[MMAP_FAULT] write fault on read-only mapping");
            return Err(EPERM);
        }
        let page_off = match page_addr.checked_sub(region.start()) {
            Some(v) => v as usize,
            None => return Err(EINVAL),
        };

        let maybe_phys = crate::mem::paging::virt_to_phys_in_table(pt_phys, page_addr);
        if let Some(phys) = maybe_phys {
            if !is_write {
                crate::debug!("[MMAP_FAULT] page already mapped {:#x}", page_addr);
                return Err(EINVAL);
            }
            let frame = match x86_64::structures::paging::PhysFrame::from_start_address(
                x86_64::PhysAddr::new(phys),
            ) {
                Ok(frame) => frame,
                Err(_) => return Err(EINVAL),
            };
            let page = x86_64::structures::paging::Page::containing_address(x86_64::VirtAddr::new(
                page_addr,
            ));
            let flags = x86_64::structures::paging::PageTableFlags::PRESENT
                | x86_64::structures::paging::PageTableFlags::WRITABLE
                | x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE
                | x86_64::structures::paging::PageTableFlags::NO_EXECUTE;
            if crate::mem::paging::map_page(page, frame, flags).is_err() {
                crate::debug!("[MMAP_FAULT] remap writable failed for {:#x}", page_addr);
                return Err(ENOMEM);
            }
            region.mark_dirty_page((page_addr - region.start()) / 4096);
            crate::debug!("[MMAP_FAULT] upgraded dirty page {:#x}", page_addr);
            return Ok(());
        }

        let file_data = region.backing().file_data();
        let copy_len = core::cmp::min(4096usize, file_data.len().saturating_sub(page_off));
        let src = if copy_len > 0 {
            &file_data[page_off..page_off + copy_len]
        } else {
            &[]
        };
        if crate::mem::paging::map_and_copy_segment_to(
            pt_phys,
            page_addr,
            copy_len as u64,
            4096,
            src,
            is_write && region.is_writable(),
            false,
        )
        .is_err()
        {
            crate::debug!(
                "[MMAP_FAULT] map_and_copy_segment_to failed for {:#x}",
                page_addr
            );
            return Err(ENOMEM);
        }
        if is_write {
            region.mark_dirty_page((page_addr - region.start()) / 4096);
        }
        crate::debug!("[MMAP_FAULT] mapped page {:#x}", page_addr);
        Ok(())
    });

    matches!(result, Some(Ok(())))
}

/// Mmapシステムコール
///
/// 匿名マッピングと file-backed マッピングの最小実装。
///
/// # 引数
/// - `addr`: ヒント仮想アドレス (0で任意)
/// - `length`: マップするサイズ
/// - `prot`: 保護フラグ (PROT_READ|PROT_WRITE = 3)
/// - `flags`: マップフラグ (MAP_ANONYMOUS=0x20, MAP_PRIVATE=0x2)
/// - `_fd`: ファイルディスクリプタ (-1 = 匿名)
///
/// # 戻り値
/// マップされた仮想アドレス、またはエラーコード
pub fn mmap(addr: u64, length: u64, prot: u64, flags: u64, fd: u64) -> u64 {
    use super::types::{EINVAL, ENOMEM};

    if length == 0 {
        return EINVAL;
    }

    // MAP_ANONYMOUS (0x20) は従来通りサポートする。
    const MAP_ANONYMOUS: u64 = 0x20;
    let anonymous = flags & MAP_ANONYMOUS != 0;

    let current_tid = match current_thread_id() {
        Some(tid) => tid,
        None => return ENOMEM,
    };
    let pid = match crate::task::with_thread(current_tid, |t| t.process_id()) {
        Some(pid) => pid,
        None => return ENOMEM,
    };

    // ページ境界に切り上げ（オーバーフロー安全）
    let size = match page_align_up(length) {
        Some(v) if v > 0 => v,
        _ => return EINVAL,
    };

    let writable = (prot & 0x2) != 0;
    let shared = (flags & 0x1) != 0;
    let file_backing = if anonymous {
        None
    } else if fd == 0 {
        return EINVAL;
    } else {
        let idx = fd as usize;
        let path = match crate::task::with_process(pid, |process| {
            process
                .fd_table()
                .get(idx)
                .and_then(|fh| fh.fs_path.clone())
        }) {
            Some(Some(path)) => path,
            _ => return EINVAL,
        };
        let data = match crate::cext::fs::read_all(&path) {
            Some(data) => data,
            None => return ENOMEM,
        };
        Some((path, data))
    };

    let result = crate::task::with_process_mut(pid, |process| {
        // mmap用のヒープ領域を現在のbrk以降に割り当てる
        // (簡易実装: brkと同じ領域を使う)
        if process.heap_start() == 0 {
            let exec_cfg = crate::config::kernel().exec;
            let default_heap_base = randomized_heap_base(
                pid,
                exec_cfg.mmap_heap_base_min,
                exec_cfg.mmap_heap_aslr_max_pages,
            );
            process.set_heap_start(default_heap_base);
            process.set_heap_end(default_heap_base);
        }

        // ユーザー空間の上限アドレスを超えるaddrを拒否
        if addr != 0 && addr > USER_SPACE_END {
            return Err(EINVAL);
        }

        let map_start = if addr != 0 {
            match page_align_up(addr) {
                Some(v) => v,
                None => return Err(EINVAL),
            }
        } else {
            // heap_endを mmap_base として使う（簡易実装）
            // 実際は別のアドレス空間管理が必要
            let base = process.heap_end();
            match page_align_up(base) {
                Some(v) => v,
                None => return Err(EINVAL),
            }
        };

        if !is_user_range(map_start, size) {
            return Err(EINVAL);
        }

        let pt_phys = match process.page_table() {
            Some(p) => p,
            None => return Err(ENOMEM),
        };

        if anonymous {
            let backing = alloc::vec![0u8; size as usize];
            let region = crate::task::MmapRegion::anonymous(
                map_start, size, prot, flags, backing, writable, shared,
            );
            if !process.add_mmap_region(region) {
                return Err(EINVAL);
            }
            if crate::mem::paging::map_and_copy_segment_to(
                pt_phys,
                map_start,
                0,
                size,
                &[],
                true,
                false,
            )
            .is_err()
            {
                return Err(ENOMEM);
            }
        } else {
            let (path, data) = match file_backing.as_ref() {
                Some((path, data)) => (path.clone(), data.clone()),
                None => return Err(EINVAL),
            };
            let region = crate::task::MmapRegion::file_backed(
                map_start, size, prot, flags, path, data, writable, shared,
            );
            if !process.add_mmap_region(region) {
                return Err(EINVAL);
            }
        }

        // heap_end を更新してアドレス空間が重ならないようにする
        if addr == 0 {
            let new_heap_end = match map_start.checked_add(size) {
                Some(v) => v,
                None => return Err(EINVAL),
            };
            process.set_heap_end(new_heap_end);
        }

        Ok(map_start)
    });

    match result {
        Some(Ok(va)) => va,
        Some(Err(e)) => e,
        None => ENOMEM,
    }
}

/// Munmapシステムコール
pub fn munmap(addr: u64, length: u64) -> u64 {
    if addr == 0 || length == 0 {
        return EINVAL;
    }
    let unmap_start = addr & !4095;
    let unmap_end = match addr.checked_add(length).and_then(page_align_up) {
        Some(v) => v,
        None => return EINVAL,
    };
    let unmap_len = match unmap_end.checked_sub(unmap_start) {
        Some(v) if v > 0 => v,
        _ => return EINVAL,
    };
    if !is_user_range(unmap_start, unmap_len) {
        return EINVAL;
    }

    let tid = match current_thread_id() {
        Some(t) => t,
        None => return ENOSYS,
    };
    let pid = match crate::task::with_thread(tid, |t| t.process_id()) {
        Some(p) => p,
        None => return ENOSYS,
    };
    let pt_phys = match crate::task::with_process(pid, |p| p.page_table()).flatten() {
        Some(p) => p,
        None => return ENOSYS,
    };

    let backing_region = crate::task::with_process_mut(pid, |process| {
        process.remove_mmap_region(unmap_start, unmap_len)
    })
    .flatten();

    if let Some(mut region) = backing_region {
        if region.is_shared() && region.is_writable() {
            let region_len = region.len();
            let path = region.backing().file_path().to_string();
            let dirty_pages = region.take_dirty_pages();
            for page_index in dirty_pages {
                let page_off = page_index.saturating_mul(4096);
                if page_off >= region_len {
                    continue;
                }
                let page_addr = unmap_start + page_off;
                let copy_len = core::cmp::min(4096u64, region_len - page_off) as usize;
                let mut page_buf = [0u8; 4096];
                if crate::syscall::copy_from_user(page_addr, &mut page_buf[..copy_len]).is_ok() {
                    let backing = region.backing_mut().file_data_mut();
                    let end = (page_off as usize).saturating_add(copy_len);
                    if end > backing.len() {
                        backing.resize(end, 0);
                    }
                    backing[page_off as usize..end].copy_from_slice(&page_buf[..copy_len]);
                    if !path.is_empty() {
                        let _ = crate::cext::fs::write_all(&path, page_off, &page_buf[..copy_len]);
                    }
                }
            }
        }
    }

    match crate::mem::paging::unmap_range_in_table(pt_phys, unmap_start, unmap_len) {
        Ok(()) => SUCCESS,
        Err(_) => EINVAL,
    }
}

/// memory_share システムコール
///
/// 指定領域を共有可能なマッピングとして扱う。
pub fn memory_share(addr: u64, length: u64, flags: u64) -> u64 {
    let _ = flags;
    if addr == 0 || length == 0 {
        return EINVAL;
    }
    let share_len = match page_align_up(length) {
        Some(v) if v > 0 => v,
        _ => return EINVAL,
    };
    if !is_user_range(addr, share_len) {
        return EINVAL;
    }
    if !super::validate_user_ptr(addr, share_len) {
        return EFAULT;
    }

    let pid = match crate::syscall::security::current_process_id() {
        Some(p) => p.as_u64(),
        None => return ENOSYS,
    };

    let ok = crate::task::with_process_mut(crate::task::ids::ProcessId::from_u64(pid), |process| {
        let region_start = addr & !4095;
        let Some(region) = process.find_mmap_region_mut(region_start) else {
            return false;
        };
        if region_start != region.start() || share_len > region.len() {
            return false;
        }
        if !region.is_writable() {
            return false;
        }
        region.set_shared(true);
        true
    })
    .unwrap_or(false);
    if ok {
        SUCCESS
    } else {
        EINVAL
    }
}

/// memory_sync システムコール
///
/// 共有マッピングの内容を backing に同期する。
pub fn memory_sync(addr: u64, length: u64, flags: u64) -> u64 {
    let _ = flags;
    if addr == 0 || length == 0 {
        return EINVAL;
    }
    let sync_len = match page_align_up(length) {
        Some(v) if v > 0 => v,
        _ => return EINVAL,
    };
    if !is_user_range(addr, sync_len) {
        return EINVAL;
    }
    if !super::validate_user_ptr(addr, sync_len) {
        return EFAULT;
    }

    let sync_start = addr & !4095;
    let pid = match crate::syscall::security::current_process_id() {
        Some(p) => p.as_u64(),
        None => return ENOSYS,
    };
    let region_start =
        match crate::task::with_process_mut(crate::task::ids::ProcessId::from_u64(pid), |process| {
            let Some(region) = process.find_mmap_region_mut(sync_start) else {
                return Err(EINVAL);
            };
            if sync_start < region.start() {
                return Err(EINVAL);
            }
            let Some(region_end) = region.end() else {
                return Err(EINVAL);
            };
            let Some(sync_end) = sync_start.checked_add(sync_len) else {
                return Err(EINVAL);
            };
            if sync_end > region_end {
                return Err(EINVAL);
            }
            if !region.is_shared() || !region.is_writable() {
                return Err(EINVAL);
            }
            Ok(region.start())
        }) {
            Some(Ok(start)) => start,
            Some(Err(e)) => return e,
            None => return ENOMEM,
        };

    let mut copied = alloc::vec![0u8; sync_len as usize];
    let mut offset = 0usize;
    while offset < copied.len() {
        let chunk_len = core::cmp::min(MEMORY_SYNC_CHUNK_BYTES, copied.len() - offset);
        let user_addr = match addr.checked_add(offset as u64) {
            Some(v) => v,
            None => return EINVAL,
        };
        if super::copy_from_user(user_addr, &mut copied[offset..offset + chunk_len]).is_err() {
            return EFAULT;
        }
        offset += chunk_len;
    }

    let backing_path =
        match crate::task::with_process_mut(crate::task::ids::ProcessId::from_u64(pid), |process| {
            let Some(region) = process.find_mmap_region_mut(region_start) else {
                return Err(EINVAL);
            };
            Ok(region.backing().file_path().to_string())
        }) {
            Some(Ok(path)) => path,
            Some(Err(e)) => return e,
            None => return ENOMEM,
        };

    if !backing_path.is_empty() {
        let mut written = 0usize;
        while written < copied.len() {
            let chunk_len = core::cmp::min(MEMORY_SYNC_CHUNK_BYTES, copied.len() - written);
            let write_off = match (written as u64).checked_add(sync_start - region_start) {
                Some(v) => v,
                None => return EINVAL,
            };
            match crate::cext::fs::write_all(
                &backing_path,
                write_off,
                &copied[written..written + chunk_len],
            ) {
                Some(n) if n == chunk_len => {}
                _ => return EIO,
            }
            written += chunk_len;
        }
    }

    let result =
        crate::task::with_process_mut(crate::task::ids::ProcessId::from_u64(pid), |process| {
            let Some(region) = process.find_mmap_region_mut(region_start) else {
                return Err(EINVAL);
            };
            Ok(writeback_shared_mmap_region(region, sync_start, &copied))
        });

    match result {
        Some(Ok(code)) => code,
        Some(Err(e)) => e,
        None => ENOMEM,
    }
}

/// Futexシステムコール
///
/// FUTEX_WAIT / FUTEX_WAKE の待機キュー方式を実装する。
/// timeout は「現在tickからの相対tick」として扱う（0は無期限）。
pub fn futex(uaddr: u64, op: u32, val: u64, timeout: u64) -> u64 {
    use super::types::EAGAIN;
    const FUTEX_WAIT: u32 = 0;
    const FUTEX_WAKE: u32 = 1;
    const FUTEX_PRIVATE_FLAG: u32 = 128;

    let op_base = op & !FUTEX_PRIVATE_FLAG;

    match op_base {
        FUTEX_WAIT => {
            if uaddr == 0 {
                return EFAULT;
            }
            let current_tid = match current_thread_id() {
                Some(tid) => tid,
                None => return ENOSYS,
            };
            // ユーザー空間アドレスの有効性を検証する
            if !super::validate_user_ptr(uaddr, 4) {
                return EFAULT;
            }
            let wake_tick = if timeout == 0 {
                NO_TIMEOUT_WAKE_TICK
            } else {
                crate::syscall::time::get_ticks().saturating_add(timeout)
            };

            crate::task::with_thread_mut(current_tid, |thread| thread.set_futex_timed_out(false));

            // 割り込み禁止区間内で「値の確認 → キュー登録 → スリープ → 最初のyield」を
            // アトミックに実行することで、wake と sleep の競合ウィンドウを排除する。
            // yield_now() 内部の switch_to_thread も CLI を実行するため、
            // without_interrupts をネストしても安全に動作する。
            let queued = x86_64::instructions::interrupts::without_interrupts(|| {
                let current_val = match crate::syscall::read_user_u32(uaddr) {
                    Ok(v) => v,
                    Err(_) => return Err(EFAULT),
                };
                if current_val != val as u32 {
                    return Err(EAGAIN);
                }
                if !register_futex_waiter(current_tid, uaddr, wake_tick) {
                    return Err(EAGAIN);
                }
                crate::task::sleep_thread(current_tid);
                // 割り込み禁止のまま最初のコンテキストスイッチを実行し、
                // sleep_thread とyield の間に wake シグナルが失われる競合を防ぐ。
                crate::task::yield_now();
                Ok(())
            });
            if let Err(err) = queued {
                return err;
            }

            enum WaitResult {
                Continue,
                Success,
                TimedOut,
            }

            // 起床後に条件を確認し、まだ待機が必要な場合のみ再度 yield する。
            loop {
                let result = x86_64::instructions::interrupts::without_interrupts(|| {
                    let timed_out = crate::task::with_thread_mut(current_tid, |thread| {
                        thread.take_futex_timed_out()
                    })
                    .unwrap_or(false);
                    if timed_out {
                        return WaitResult::TimedOut;
                    }

                    if !futex_waiter_exists(current_tid, uaddr) {
                        return WaitResult::Success;
                    }

                    if wake_tick != NO_TIMEOUT_WAKE_TICK
                        && crate::syscall::time::get_ticks() >= wake_tick
                    {
                        if remove_futex_waiter_by_tid(current_tid) {
                            crate::task::with_thread_mut(current_tid, |thread| {
                                thread.set_futex_timed_out(false);
                            });
                            return WaitResult::TimedOut;
                        }
                        let timed_out = crate::task::with_thread_mut(current_tid, |thread| {
                            thread.take_futex_timed_out()
                        })
                        .unwrap_or(false);
                        return if timed_out {
                            WaitResult::TimedOut
                        } else {
                            WaitResult::Success
                        };
                    }

                    WaitResult::Continue
                });

                match result {
                    WaitResult::Continue => crate::task::yield_now(),
                    WaitResult::Success => return SUCCESS,
                    WaitResult::TimedOut => return ETIMEDOUT,
                }
            }
        }
        FUTEX_WAKE => {
            if uaddr == 0 {
                return EFAULT;
            }
            if !super::validate_user_ptr(uaddr, 4) {
                return EFAULT;
            }
            let max_wake = core::cmp::min(val as usize, MAX_FUTEX_WAITERS);
            if max_wake == 0 {
                return 0;
            }

            let mut wake_list = [None; MAX_FUTEX_WAITERS];
            let mut wake_count = 0usize;
            {
                let mut queue = FUTEX_WAIT_QUEUE.lock();
                for slot in queue.iter_mut() {
                    if wake_count >= max_wake {
                        break;
                    }
                    if let Some(entry) = *slot {
                        if entry.uaddr == uaddr {
                            *slot = None;
                            wake_list[wake_count] = Some(entry.tid);
                            wake_count += 1;
                        }
                    }
                }
            }

            for tid in wake_list.iter().take(wake_count).flatten() {
                crate::task::with_thread_mut(*tid, |thread| thread.set_futex_timed_out(false));
                crate::task::wake_thread(*tid);
            }
            wake_count as u64
        }
        _ => ENOSYS,
    }
}

/// arch_prctlシステムコール
///
/// TLS 用の FS ベースレジスタを設定する
pub fn arch_prctl(code: u64, addr: u64) -> u64 {
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;

    match code {
        ARCH_SET_FS => {
            if addr > USER_SPACE_END {
                return EINVAL;
            }
            // glibc の起動シーケンスでは FS を切り替える最中に stack protector が
            // 動くことがあるため、旧FS上のガード値を新FSへ引き継ぐ。
            // （mapped かつユーザー範囲内の場合のみ）
            let old_fs = if let Some(tid) = current_thread_id() {
                crate::task::with_thread(tid, |t| t.fs_base()).unwrap_or(0)
            } else {
                unsafe { crate::cpu::read_fs_base() }
            };
            if old_fs >= 0x1000 && addr >= 0x1000 && old_fs != addr {
                for off in [0x28u64, 0x30u64] {
                    let src = old_fs.saturating_add(off);
                    let dst = addr.saturating_add(off);
                    if super::validate_user_ptr(src, 8) && super::validate_user_ptr(dst, 8) {
                        if let Ok(val) = crate::syscall::read_user_u64(src) {
                            let _ = crate::syscall::write_user_u64(dst, val);
                        }
                    }
                }
            }
            // FS ベースレジスタを設定 (WRFSBASE または IA32_FS_BASE MSR)
            unsafe {
                crate::cpu::write_fs_base(addr);
            }
            // 現在のスレッドに FS base を記録 (コンテキストスイッチ時に復元するため)
            if let Some(tid) = current_thread_id() {
                crate::task::with_thread_mut(tid, |t| t.set_fs_base(addr));
            }
            SUCCESS
        }
        ARCH_GET_FS => {
            let val = unsafe { crate::cpu::read_fs_base() };
            // addrが指すメモリに書き込む
            if addr == 0 {
                return EFAULT;
            }
            // ユーザー空間アドレスの有効性を検証する
            if !super::validate_user_ptr(addr, 8) {
                return EFAULT;
            }
            match crate::syscall::write_user_u64(addr, val) {
                Ok(()) => SUCCESS,
                Err(e) => e,
            }
        }
        _ => EINVAL,
    }
}

/// sigaltstack システムコール（最小実装）
///
/// 互換目的で成功を返す。現状 alt stack の切り替えは行わない。
pub fn sigaltstack(_ss: u64, _old_ss: u64) -> u64 {
    SUCCESS
}

/// set_robust_list システムコール（最小実装）
///
/// glibc 初期化互換のため成功を返す。
pub fn set_robust_list(_head: u64, _len: u64) -> u64 {
    SUCCESS
}

/// getrandom システムコール（最小実装）
///
/// カーネル内の軽量PRNGでバイト列を生成して返す。
pub fn getrandom(buf_ptr: u64, len: u64, _flags: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    if buf_ptr == 0 || !super::validate_user_ptr(buf_ptr, len) {
        return EFAULT;
    }
    let mut state = crate::syscall::time::get_ticks()
        ^ buf_ptr.rotate_left(17)
        ^ len.rotate_left(7)
        ^ 0x9E37_79B9_7F4A_7C15;
    let mut out = alloc::vec![0u8; len as usize];
    for b in out.iter_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (state >> 24) as u8;
    }
    match crate::syscall::copy_to_user(buf_ptr, &out) {
        Ok(()) => len,
        Err(e) => e,
    }
}

/// FindProcessByNameシステムコール
///
/// プロセス名から、IPC送信先として使えるスレッドIDを検索する
///
/// # 引数
/// - `name_ptr`: プロセス名のポインタ
/// - `len`: プロセス名の長さ
///
/// # 戻り値
/// 見つかった場合はスレッドID、見つからない場合は0
pub fn find_process_by_name(name_ptr: u64, len: u64) -> u64 {
    use crate::task;
    use core::str;

    if name_ptr == 0 || len == 0 || len > 64 {
        return 0;
    }

    // capability 強制:
    // 名前解決で任意サービスのスレッドIDが分かると、そのまま IPC を送れてしまう。
    // 「サービスへ接続する」操作として `ipc.client` を要求する。
    // ただしサービス自身が READY 通知などで名前解決を行うため、`ipc.server` も許可する。
    if !caller_has_process_inspect_capability()
        && !crate::syscall::security::caller_has_any_capability(&[
            crate::capability::Capability::IpcClient,
            crate::capability::Capability::IpcServer,
        ])
    {
        return 0;
    }

    let mut name_buf = [0u8; 64];
    if crate::syscall::copy_from_user(name_ptr, &mut name_buf[..len as usize]).is_err() {
        return 0;
    }
    let name = match str::from_utf8(&name_buf[..len as usize]) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let pid = match task::find_process_id_by_name(name) {
        Some(pid) => pid,
        None => return 0,
    };

    // IPCの宛先はプロセスIDではなくスレッドIDなので、
    // 対象プロセスに属する先頭スレッドIDを返す。
    let mut thread_id: Option<u64> = None;
    task::for_each_thread(|thread| {
        if thread_id.is_none()
            && thread.process_id() == pid
            && thread.state() != task::ThreadState::Terminated
        {
            thread_id = Some(thread.id().as_u64());
        }
    });

    thread_id.unwrap_or(0)
}
