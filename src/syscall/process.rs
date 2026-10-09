//! プロセス管理関連のシステムコール

use super::types::{EAGAIN, EFAULT, EINVAL, ENOMEM, ENOSPC, ENOSYS, EPERM, ESRCH, SUCCESS};
use crate::task::ThreadId;
use alloc::string::ToString;
use alloc::sync::Arc;
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

pub fn get_thread_security_context(sender_endpoint: u64, output: u64, output_len: u64) -> u64 {
    if output_len < core::mem::size_of::<mnu_abi::ThreadSecurityContext>() as u64 {
        return EINVAL;
    }
    let thread_id = if sender_endpoint == 0 {
        crate::task::current_thread_id().map(|thread_id| thread_id.as_u64())
    } else {
        if !crate::syscall::security::caller_has_any_capability(&[
            crate::capability::Capability::CapabilitiesManage,
            crate::capability::Capability::ProcessInspect,
        ]) {
            return EPERM;
        }
        crate::syscall::ipc::resolve_sender_thread_id(sender_endpoint)
    };
    let Some(thread_id) = thread_id else {
        return EINVAL;
    };
    let Some(pid) = crate::task::thread_to_process_id(thread_id) else {
        return EINVAL;
    };
    let Some(context) = crate::task::with_process(pid, |process| {
        let credentials = process.credentials();
        let mut context = mnu_abi::ThreadSecurityContext::default();
        context.process_id = pid.as_u64();
        context.thread_id = thread_id;
        context.effective_uid = credentials.effective_uid();
        context.effective_gid = credentials.effective_gid();
        if let Some(identity) = process.application_identity() {
            let package = identity.package_id().as_bytes();
            let developer = identity.developer_id().as_bytes();
            if package.len() <= mnu_abi::APPLICATION_ID_FIELD_LEN
                && developer.len() <= mnu_abi::APPLICATION_ID_FIELD_LEN
            {
                context.provenance = match identity.provenance() {
                    crate::task::process::ApplicationProvenance::BuiltIn => 1,
                    crate::task::process::ApplicationProvenance::VerifiedPackage => 2,
                    crate::task::process::ApplicationProvenance::Development => 3,
                };
                context.subject_key_id = *identity.subject_key_id();
                context.package_id_len = package.len() as u16;
                context.developer_id_len = developer.len() as u16;
                context.package_id[..package.len()].copy_from_slice(package);
                context.developer_id[..developer.len()].copy_from_slice(developer);
            }
        }
        context
    }) else {
        return EINVAL;
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&context as *const mnu_abi::ThreadSecurityContext).cast::<u8>(),
            core::mem::size_of::<mnu_abi::ThreadSecurityContext>(),
        )
    };
    crate::syscall::copy_to_user(output, bytes)
        .map(|_| SUCCESS)
        .unwrap_or_else(|error| error)
}

/// ユーザー空間の上限アドレス (x86-64 canonical hole 下側)
const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_FFFF;
use crate::task::current_thread_id;
use crate::task::scheduler::exit_current_process;

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

    // ProcessExit/_exit は同一プロセスの全スレッドを終了させる。
    // ここで現在スレッドだけを止めると、GUIツールキットなどがワーカー
    // スレッドを持つ場合にプロセスが Zombie にならず waitpid が永久待機する。
    exit_current_process(exit_code as i32)
}

/// List processes into a user-supplied buffer.
/// arg0 = user buffer ptr, arg1 = buffer length in bytes.
pub fn list_processes(buf_ptr: u64, buf_len: u64) -> u64 {
    use crate::task::ProcessState;

    if !caller_has_process_inspect_capability() {
        return EPERM;
    }

    const RECORD_SIZE: usize = 112;
    if buf_ptr == 0 {
        return 0;
    }
    let max_bytes = buf_len as usize;
    let max_entries = max_bytes / RECORD_SIZE;
    if max_entries == 0 {
        return 0;
    }

    let mut thread_metrics: Vec<(crate::task::ProcessId, u64, u64)> = Vec::new();
    crate::task::for_each_thread(|thread| {
        let process_id = thread.process_id();
        if let Some((_, count, ticks)) = thread_metrics
            .iter_mut()
            .find(|(candidate, _, _)| *candidate == process_id)
        {
            *count = count.saturating_add(1);
            *ticks = ticks.saturating_add(thread.cpu_ticks());
        } else {
            thread_metrics.push((process_id, 1, thread.cpu_ticks()));
        }
    });

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
        };
        out_buf[16..24].copy_from_slice(&state_num.to_ne_bytes());
        let parent = proc.parent_id().map_or(0, |pid| pid.as_u64());
        out_buf[24..32].copy_from_slice(&parent.to_ne_bytes());
        let (thread_count, cpu_ticks) = thread_metrics
            .iter()
            .find(|(process_id, _, _)| *process_id == proc.id())
            .map(|(_, count, ticks)| (*count, *ticks))
            .unwrap_or((0, 0));
        out_buf[32..40].copy_from_slice(&cpu_ticks.to_ne_bytes());
        out_buf[40..48].copy_from_slice(&proc.mapped_memory_bytes().to_ne_bytes());
        out_buf[48..56].copy_from_slice(&thread_count.to_ne_bytes());
        // Signed applications expose their package identity. Other processes use
        // the explicit name supplied when they were created; the kernel does not
        // infer user-space roles from executable paths or filename conventions.
        let name = proc
            .application_identity()
            .map(|identity| identity.package_id())
            .unwrap_or_else(|| proc.name());
        // name at offset 56; the fixed 112-byte ABI leaves 56 bytes for UTF-8.
        let name_bytes = name.as_bytes();
        let copy_len = core::cmp::min(RECORD_SIZE - 56, name_bytes.len());
        out_buf[56..56 + copy_len].copy_from_slice(&name_bytes[..copy_len]);
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

fn clone_current_process() -> u64 {
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
    let mut live_threads = 0usize;
    crate::task::for_each_thread(|thread| {
        if thread.process_id() == parent_pid
            && thread.state() != crate::task::ThreadState::Terminated
        {
            live_threads += 1;
        }
    });
    if live_threads != 1 {
        crate::audit::log(
            crate::audit::AuditEventKind::Policy,
            "fork rejected until cross-CPU TLB shootdown is available",
        );
        return EAGAIN;
    }
    let parent_has_mmio =
        crate::task::with_process(parent_pid, |p| p.has_mmio_mappings()).unwrap_or(false);
    if parent_has_mmio {
        crate::audit::log(
            crate::audit::AuditEventKind::Policy,
            "fork rejected while borrowed MMIO mappings are active",
        );
        return EPERM;
    }

    let (
        parent_priv,
        parent_priority,
        parent_foreground,
        parent_caps,
        parent_credentials,
        parent_pt,
        heap_start,
        heap_end,
        ipc_mapping_end,
        stack_bottom,
        stack_top,
        parent_exe_path,
        parent_security_identity,
        parent_limits,
        parent_memory_regions,
        parent_dma_buffers,
        parent_object_handles,
        parent_launch_context,
    ) = match crate::task::with_process(parent_pid, |p| {
        (
            p.privilege(),
            p.priority(),
            p.is_foreground(),
            p.capabilities().clone(),
            p.credentials(),
            p.page_table(),
            p.heap_start(),
            p.heap_end(),
            p.ipc_mapping_end(),
            p.stack_bottom(),
            p.stack_top(),
            p.exe_path().to_string(),
            p.application_identity().cloned(),
            p.resource_limits(),
            p.clone_memory_regions_for_fork(),
            p.dma_buffers().to_vec(),
            p.clone_object_handles(),
            p.clone_launch_context(),
        )
    }) {
        Some(v) => v,
        None => return ENOSYS,
    };
    let parent_pt = match parent_pt {
        Some(pt) => pt,
        None => return ENOSYS,
    };

    let child_pt = match crate::mem::paging::clone_user_page_table(parent_pt, |vaddr| {
        if parent_dma_buffers.iter().any(|dma| {
            dma.end()
                .is_some_and(|end| vaddr >= dma.virt_start() && vaddr < end)
        }) {
            return crate::mem::paging::ForkPagePolicy::Exclude;
        }
        if let Some(region) = parent_memory_regions
            .iter()
            .find(|region| region.contains(vaddr))
        {
            if region.is_shared() {
                crate::mem::paging::ForkPagePolicy::Shared
            } else {
                crate::mem::paging::ForkPagePolicy::PrivateWritable
            }
        } else {
            crate::mem::paging::ForkPagePolicy::Private
        }
    }) {
        Ok(pt) => pt,
        Err(err) => {
            crate::warn!("fork: clone_user_page_table failed: {:?}", err);
            return ENOMEM;
        }
    };

    let (user_context, parent_fs) = crate::task::with_thread(parent_tid, |thread| {
        (thread.syscall_user_context(), thread.fs_base())
    })
    .unwrap_or((crate::task::thread::SyscallUserContext::empty(), 0));
    if user_context.rip == 0 || user_context.rsp == 0 {
        let _ = crate::mem::paging::destroy_user_page_table(child_pt);
        return ENOSYS;
    }

    let mut child_proc = crate::task::Process::new("clone", parent_priv, None, parent_priority);
    child_proc.set_foreground(parent_foreground);
    child_proc.set_capabilities_for_exec(parent_caps);
    child_proc.set_credentials_for_exec(parent_credentials);
    child_proc.set_page_table(child_pt);
    child_proc.set_heap_start(heap_start);
    child_proc.set_heap_end(heap_end);
    child_proc.set_ipc_mapping_end(ipc_mapping_end);
    child_proc.set_stack_bottom(stack_bottom);
    child_proc.set_stack_top(stack_top);
    child_proc.set_exe_path(&parent_exe_path);
    if let Some(identity) = parent_security_identity {
        child_proc.set_application_identity(identity);
    }
    child_proc.set_resource_limits(parent_limits);
    child_proc.set_memory_regions(parent_memory_regions);
    child_proc.set_object_handles(parent_object_handles);
    child_proc.set_launch_context(parent_launch_context);
    crate::debug!(
        "[STACK_INIT] FORK child: stack_bottom={:#x}, stack_top={:#x}",
        stack_bottom,
        stack_top
    );
    let child_pid = child_proc.id();
    let child_object = child_proc.process_object();
    if crate::task::add_process(child_proc).is_none() {
        let _ = crate::mem::paging::destroy_user_page_table(child_pt);
        return ENOMEM;
    }

    let child_handle = match crate::task::with_process_mut(parent_pid, |process| {
        let rights = crate::task::HandleRights::WAIT
            .union(crate::task::HandleRights::SIGNAL)
            .union(crate::task::HandleRights::DUPLICATE)
            .union(crate::task::HandleRights::TRANSFER);
        process
            .object_handles_mut()
            .insert(crate::task::ObjectHandleEntry::new(
                crate::task::KernelObject::Process(child_object),
                rights,
            ))
    })
    .flatten()
    {
        Some(handle) => handle,
        None => {
            let _ = crate::task::remove_process(child_pid);
            let _ = crate::mem::paging::destroy_user_page_table(child_pt);
            return ENOSPC;
        }
    };

    let kstack_size = crate::config::kernel().exec.kernel_thread_stack_size;
    let kstack = match crate::task::thread::allocate_kernel_stack_in_table(kstack_size, child_pt) {
        Some(s) => s,
        None => {
            let _ = crate::task::with_process_mut(parent_pid, |process| {
                process.object_handles_mut().close(child_handle)
            });
            let _ = crate::task::remove_process(child_pid);
            let _ = crate::mem::paging::destroy_user_page_table(child_pt);
            return ENOMEM;
        }
    };
    let mut child_thread = crate::task::Thread::new_fork_child(
        child_pid,
        user_context,
        parent_fs,
        kstack,
        kstack_size,
    );
    child_thread.suspend();
    if crate::task::add_thread(child_thread).is_none() {
        crate::task::free_kernel_stack(kstack);
        let _ = crate::task::with_process_mut(parent_pid, |process| {
            process.object_handles_mut().close(child_handle)
        });
        let _ = crate::task::remove_process(child_pid);
        let _ = crate::mem::paging::destroy_user_page_table(child_pt);
        return ENOMEM;
    }

    child_handle.raw() as u64
}

/// Clones the current process using native mnu semantics. The parent receives
/// a process-local handle for the child; the child resumes with a zero return
/// value from the cloned syscall frame.
pub fn clone_process() -> u64 {
    clone_current_process()
}

/// Suspends every thread in the current process until a holder of a process
/// handle resumes it. This is a native lifecycle primitive; the kernel does
/// not assign any POSIX signal or job-control meaning to the suspension.
pub fn suspend_current_process() -> u64 {
    let Some(process_id) = crate::syscall::security::current_process_id() else {
        return EINVAL;
    };
    let Some(thread_id) = crate::task::current_thread_id() else {
        return ESRCH;
    };
    if crate::task::suspend_process_threads(process_id) == 0 {
        return ESRCH;
    }
    while crate::task::with_thread(thread_id, |thread| thread.is_scheduling_suspended())
        .unwrap_or(false)
    {
        crate::task::yield_now();
        core::hint::spin_loop();
    }
    SUCCESS
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

/// Resolves one page of a native memory region after a user page fault.
pub fn handle_user_memory_fault(fault_addr: u64, is_write: bool, is_execute: bool) -> bool {
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
        "[MEMORY_FAULT] addr={:#x} page={:#x} write={}",
        fault_addr,
        page_addr,
        is_write
    );
    let resident = crate::task::with_process_mut(pid, |process| {
        let pt_phys = match process.page_table() {
            Some(p) => p,
            None => return Err(EINVAL),
        };
        let region = match process.find_memory_region_mut(fault_addr) {
            Some(region) => region,
            None => {
                crate::debug!("[MEMORY_FAULT] no region for {:#x}", fault_addr);
                return Err(EINVAL);
            }
        };
        crate::debug!(
            "[MEMORY_FAULT] region start={:#x} len={:#x} writable={} shared={}",
            region.start(),
            region.len(),
            region.allows_write_at(fault_addr),
            region.is_shared()
        );
        if !region.allows_read_at(fault_addr) {
            crate::debug!("[MEMORY_FAULT] access fault on inaccessible mapping");
            return Err(EPERM);
        }
        if is_write && !region.allows_write_at(fault_addr) {
            crate::debug!("[MEMORY_FAULT] write fault on read-only mapping");
            return Err(EPERM);
        }
        if is_execute && !region.allows_execute_at(fault_addr) {
            crate::debug!("[MEMORY_FAULT] instruction fault on non-executable mapping");
            return Err(EPERM);
        }
        if crate::mem::paging::is_user_range_mapped_in_table(pt_phys, page_addr, 1) {
            if !is_write {
                crate::debug!("[MEMORY_FAULT] page already mapped {:#x}", page_addr);
                return Err(EINVAL);
            }
            if region.is_shared() {
                if let Some(object) = region.backing().file_object() {
                    let page_offset = page_addr.checked_sub(region.start()).ok_or(EINVAL)?;
                    let file_offset = region
                        .backing()
                        .file_offset()
                        .checked_add(page_offset)
                        .ok_or(EINVAL)?;
                    object.mark_page_dirty(file_offset / 4096)?;
                }
            }
            if crate::mem::paging::protect_range_in_table(
                pt_phys, page_addr, 4096, true, true, false,
            )
            .is_err()
            {
                crate::debug!("[MEMORY_FAULT] remap writable failed for {:#x}", page_addr);
                return Err(ENOMEM);
            }
            region.mark_dirty_page((page_addr - region.start()) / 4096);
            crate::debug!("[MEMORY_FAULT] upgraded dirty page {:#x}", page_addr);
            return Ok(true);
        }
        Ok(false)
    });
    match resident {
        Some(Ok(true)) => return true,
        Some(Ok(false)) => {}
        _ => return false,
    }

    let plan = crate::task::with_process(pid, |process| {
        let pt_phys = process.page_table().ok_or(EINVAL)?;
        let region = process.find_memory_region(fault_addr).ok_or(EINVAL)?;
        if !region.allows_read_at(fault_addr)
            || (is_write && !region.allows_write_at(fault_addr))
            || (is_execute && !region.allows_execute_at(fault_addr))
        {
            return Err(EPERM);
        }
        let page_offset = page_addr.checked_sub(region.start()).ok_or(EINVAL)?;
        let pager = match region.backing().file_object() {
            Some(object) => {
                let file_offset = region
                    .backing()
                    .file_offset()
                    .checked_add(page_offset)
                    .ok_or(EINVAL)?;
                Some((object.clone(), file_offset / 4096))
            }
            None => None,
        };
        let shared_file = region.is_shared() && pager.is_some();
        Ok((
            pt_phys,
            region.start(),
            shared_file,
            pager,
        ))
    });
    let Some(Ok((pt_phys, region_start, shared_file, pager))) = plan else {
        return false;
    };

    let page = match pager.as_ref() {
        Some((object, page_index)) if !shared_file => match object.page(*page_index) {
            Ok(page) => Some(page),
            Err(_) => return false,
        },
        Some(_) => None,
        None => Some(Arc::new([0u8; crate::mem::vm_object::PAGE_BYTES])),
    };
    // Loading a shared cache page may call provider IPC. Pin it before taking
    // the process-table lock; the retained frame also prevents cache eviction
    // between preparation and installation into the revalidated mapping.
    let shared_page = match pager.as_ref() {
        Some((object, page_index)) if shared_file => match object.prepare_shared_page(*page_index) {
            Ok(page) => Some(page),
            Err(_) => return false,
        },
        _ => None,
    };

    let result = crate::task::with_process_mut(pid, |process| {
        if process.page_table() != Some(pt_phys) {
            return Err(EINVAL);
        }
        let region = process.find_memory_region_mut(fault_addr).ok_or(EINVAL)?;
        if region.start() != region_start
            || !region.allows_read_at(fault_addr)
            || (is_write && !region.allows_write_at(fault_addr))
            || (is_execute && !region.allows_execute_at(fault_addr))
        {
            return Err(EPERM);
        }
        let same_backing = match (pager.as_ref(), region.backing().file_object()) {
            (Some((planned, page_index)), Some(current)) => {
                Arc::ptr_eq(planned, current)
                    && region
                        .backing()
                        .file_offset()
                        .checked_add(page_addr - region.start())
                        .is_some_and(|offset| offset / 4096 == *page_index)
                    && region.is_shared() == shared_file
            }
            (None, None) => true,
            _ => false,
        };
        if !same_backing {
            return Err(EINVAL);
        }
        let executable = region.allows_execute_at(fault_addr);
        if crate::mem::paging::is_user_range_mapped_in_table(pt_phys, page_addr, 1) {
            return Ok(());
        }
        if shared_file {
            let Some((object, page_index)) = pager.as_ref() else {
                return Err(EINVAL);
            };
            shared_page
                .as_ref()
                .ok_or(EINVAL)?
                .map_to(pt_phys, page_addr, false, executable)?;
            if is_write {
                object.mark_page_dirty(*page_index)?;
                if crate::mem::paging::protect_user_page_if_mapped(
                    pt_phys, page_addr, true, true, executable,
                )
                .is_err()
                {
                    return Err(ENOMEM);
                }
            }
        } else {
            let page = page.as_ref().ok_or(EINVAL)?;
            if crate::mem::paging::map_and_copy_segment_to(
                pt_phys,
                page_addr,
                crate::mem::vm_object::PAGE_BYTES as u64,
                4096,
                page.as_slice(),
                is_write && region.allows_write_at(fault_addr),
                executable,
            )
            .is_err()
            {
                crate::debug!(
                    "[MEMORY_FAULT] map_and_copy_segment_to failed for {:#x}",
                    page_addr
                );
                return Err(ENOMEM);
            }
        }
        if is_write {
            region.mark_dirty_page((page_addr - region.start()) / 4096);
        }
        crate::debug!("[MEMORY_FAULT] mapped page {:#x}", page_addr);
        Ok(())
    });

    matches!(result, Some(Ok(())))
}

/// Maps anonymous memory or a mappable kernel object into the current address
/// space. A zero `backing_handle` selects anonymous memory. All other values
/// are process-local object handles; descriptor numbers are never accepted.
pub fn memory_map(
    addr: u64,
    length: u64,
    access: u64,
    options: u64,
    backing_handle: u64,
    backing_offset: u64,
) -> u64 {
    use super::types::{EINVAL, ENOMEM};

    if length == 0 {
        return EINVAL;
    }
    if access & !mnu_abi::MEMORY_ACCESS_ALL != 0
        || options & !mnu_abi::MEMORY_MAP_OPTIONS_ALL != 0
        || access & (mnu_abi::MEMORY_ACCESS_WRITE | mnu_abi::MEMORY_ACCESS_EXECUTE)
            == mnu_abi::MEMORY_ACCESS_WRITE | mnu_abi::MEMORY_ACCESS_EXECUTE
    {
        return EINVAL;
    }
    let exact = options & mnu_abi::MEMORY_MAP_EXACT != 0;
    let shared = options & mnu_abi::MEMORY_MAP_SHARED != 0;
    if exact && (addr == 0 || addr & 4095 != 0) {
        return EINVAL;
    }

    const MAX_MEMORY_BACKING_BYTES: u64 = 256 * 1024 * 1024;
    let anonymous = backing_handle == 0;
    if (anonymous && backing_offset != 0) || (!anonymous && backing_offset & 4095 != 0) {
        return EINVAL;
    }

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
    if size > MAX_MEMORY_BACKING_BYTES {
        crate::warn!(
            "process::memory_map refusing oversized mapping length={:#x} aligned={:#x}",
            length,
            size
        );
        return ENOMEM;
    }
    if !anonymous && backing_offset.checked_add(size).is_none() {
        return EINVAL;
    }

    let present = access != 0;
    let writable = access & mnu_abi::MEMORY_ACCESS_WRITE != 0;
    let executable = access & mnu_abi::MEMORY_ACCESS_EXECUTE != 0;
    let file_backing = if anonymous {
        None
    } else {
        let mut rights = crate::task::HandleRights::MAP.union(crate::task::HandleRights::READ);
        if shared && writable {
            rights = rights.union(crate::task::HandleRights::WRITE);
        }
        let (object, granted_rights) =
            match crate::syscall::handle::object_with_rights(backing_handle, rights) {
                Ok(result) => result,
                Err(error) => return error,
            };
        let mut max_access = if shared && !granted_rights.contains(crate::task::HandleRights::WRITE)
        {
            mnu_abi::MEMORY_ACCESS_ALL & !mnu_abi::MEMORY_ACCESS_WRITE
        } else {
            mnu_abi::MEMORY_ACCESS_ALL
        };
        let object = match object {
            crate::task::KernelObject::File(file) => {
                let vnode = file.open.lock().vnode.as_ref().cloned();
                match vnode {
                    Some(vnode) if !vnode.is_directory() => {
                        Arc::new(crate::mem::vm_object::VmObject::file(vnode))
                    }
                    _ => return EINVAL,
                }
            }
            crate::task::KernelObject::Provider(provider) => {
                let identity = match crate::syscall::handle::provider_memory_object(&provider) {
                    Ok(identity) => identity,
                    Err(error) => return error,
                };
                Arc::new(crate::mem::vm_object::VmObject::provider(
                    provider, identity,
                ))
            }
            crate::task::KernelObject::VmObject(object) => {
                let object_length = match object.memory_length() {
                    Some(length) => length,
                    None => return EINVAL,
                };
                if !backing_offset
                    .checked_add(size)
                    .is_some_and(|end| end <= object_length)
                {
                    return EINVAL;
                }
                max_access &= !mnu_abi::MEMORY_ACCESS_EXECUTE;
                if access & !max_access != 0 {
                    return crate::syscall::EACCES;
                }
                object
            }
            _ => return EINVAL,
        };
        Some((object, backing_offset, max_access))
    };

    let result = crate::task::with_process_mut(pid, |process| {
        // mmap用のヒープ領域を現在のbrk以降に割り当てる
        // (簡易実装: brkと同じ領域を使う)
        if process.heap_start() == 0 {
            let exec_cfg = crate::config::kernel().exec;
            let default_heap_base = randomized_heap_base(
                pid,
                exec_cfg.memory_map_base_min,
                exec_cfg.memory_map_aslr_max_pages,
            );
            process.set_heap_start(default_heap_base);
            process.set_heap_end(default_heap_base);
        }

        // ユーザー空間の上限アドレスを超えるaddrを拒否
        if addr != 0 && addr > USER_SPACE_END {
            return Err(EINVAL);
        }

        let pt_phys = match process.page_table() {
            Some(p) => p,
            None => return Err(ENOMEM),
        };

        let range_is_available = |candidate: u64| {
            is_user_range(candidate, size)
                && !crate::mem::paging::is_user_range_occupied_in_table(pt_phys, candidate, size)
                && process.memory_regions().iter().all(|region| {
                    let Some(candidate_end) = candidate.checked_add(size) else {
                        return false;
                    };
                    let Some(region_end) = region.end() else {
                        return false;
                    };
                    candidate_end <= region.start() || candidate >= region_end
                })
        };

        let requested = if addr == 0 {
            None
        } else {
            match page_align_up(addr) {
                Some(value) => Some(value),
                None => return Err(EINVAL),
            }
        };
        let map_start = if exact {
            let candidate = requested.ok_or(EINVAL)?;
            if !range_is_available(candidate) {
                return Err(EINVAL);
            }
            candidate
        } else if requested.is_some_and(range_is_available) {
            requested.unwrap_or(0)
        } else {
            let mut candidate = match page_align_up(process.heap_end()) {
                Some(v) => v,
                None => return Err(EINVAL),
            };
            while !range_is_available(candidate) {
                candidate = match candidate.checked_add(4096) {
                    Some(v) if is_user_range(v, size) => v,
                    _ => return Err(ENOMEM),
                };
            }
            candidate
        };

        if !is_user_range(map_start, size) {
            crate::debug!("process::memory_map out of range");
            return Err(EINVAL);
        }

        if anonymous {
            let region = crate::task::MemoryRegion::anonymous(
                map_start, size, access, options, writable, shared,
            );
            if !process.add_memory_region(region) {
                crate::debug!("process::memory_map overlap");
                return Err(EINVAL);
            }
            // An inaccessible anonymous region reserves virtual space only.
            // MemoryProtect and the existing fault handler commit pages later.
            if present
                && crate::mem::paging::map_and_copy_segment_to(
                    pt_phys,
                    map_start,
                    0,
                    size,
                    &[],
                    writable,
                    executable,
                )
                .is_err()
            {
                let _ = crate::mem::paging::unmap_range_in_table(pt_phys, map_start, size);
                process.remove_memory_region(map_start, size);
                return Err(ENOMEM);
            }
        } else {
            let (object, file_offset, max_access) = match file_backing {
                Some(backing) => backing,
                None => return Err(EINVAL),
            };
            let region = crate::task::MemoryRegion::file_backed(
                map_start,
                size,
                access,
                options,
                object,
                file_offset,
                writable,
                shared,
                max_access,
            );
            if !process.add_memory_region(region) {
                return Err(EINVAL);
            }
        }

        // heap_end を更新してアドレス空間が重ならないようにする
        if !exact {
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

/// Removes native virtual-memory mappings from the current address space.
pub fn memory_unmap(addr: u64, length: u64) -> u64 {
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

    let overlaps_dma = crate::task::with_process(pid, |process| {
        process
            .find_dma_buffer_by_addr(unmap_start, unmap_len)
            .is_some()
    })
    .unwrap_or(false);
    if overlaps_dma {
        return EPERM;
    }

    let mmio_mapping = crate::task::with_process_mut(pid, |process| {
        process.remove_mmio_mapping(unmap_start, unmap_len)
    })
    .flatten();
    if let Some(_mapping) = mmio_mapping {
        return match crate::mem::paging::unmap_range_in_table_preserve_frames(
            pt_phys,
            unmap_start,
            unmap_len,
        ) {
            Ok(()) => SUCCESS,
            Err(_) => EINVAL,
        };
    }

    let overlaps_mmio = crate::task::with_process(pid, |process| {
        process
            .find_mmio_mapping_by_addr(unmap_start, unmap_len)
            .is_some()
    })
    .unwrap_or(false);
    if overlaps_mmio {
        return EINVAL;
    }

    let removed = match crate::task::with_process_mut(pid, |process| {
        process.remove_memory_range(unmap_start, unmap_len)
    })
    .flatten()
    {
        Some(removed) => removed,
        None => return EINVAL,
    };
    if crate::mem::paging::unmap_range_in_table(pt_phys, unmap_start, unmap_len).is_err() {
        return EINVAL;
    }
    for region in removed {
        if region.is_shared() && region.permits_access(mnu_abi::MEMORY_ACCESS_WRITE) {
            if let Some(object) = region.backing().file_object() {
                if let Err(errno) = object.flush_range(region.backing().file_offset(), region.len())
                {
                    return errno;
                }
            }
        }
    }
    SUCCESS
}

/// memory_share システムコール
///
/// 匿名領域を共有可能なマッピングとして扱う。
/// ファイルbackingの共有化はHandle権限を検証するMemoryMap経路で行う。
pub fn memory_share(addr: u64, length: u64, options: u64) -> u64 {
    if options != 0 || addr == 0 || length == 0 || addr & 4095 != 0 {
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
        let Some(region) = process.find_memory_region_mut(region_start) else {
            return false;
        };
        if region_start != region.start() || share_len > region.len() {
            return false;
        }
        if !region.allows_write_range(region_start, share_len) {
            return false;
        }
        region.set_shared(true)
    })
    .unwrap_or(false);
    if ok { SUCCESS } else { EINVAL }
}

pub fn alloc_shared_pages(
    page_count_raw: u64,
    phys_pages_ptr: u64,
    phys_page_count_raw: u64,
    options: u64,
) -> u64 {
    let _ = options;
    if page_count_raw == 0 || (phys_pages_ptr != 0 && phys_page_count_raw < page_count_raw) {
        return EINVAL;
    }
    let Ok(page_count) = usize::try_from(page_count_raw) else {
        return EINVAL;
    };
    if page_count > 262_144 {
        return EINVAL;
    }
    let out_len = match page_count_raw.checked_mul(8) {
        Some(v) => v,
        None => return EINVAL,
    };
    if phys_pages_ptr != 0 && !super::validate_user_ptr(phys_pages_ptr, out_len) {
        return EFAULT;
    }

    let pid = match crate::syscall::security::current_process_id() {
        Some(pid) => pid,
        None => return ENOSYS,
    };
    let pt_phys = match crate::task::with_process(pid, |process| process.page_table()).flatten() {
        Some(pt) => pt,
        None => return ENOMEM,
    };
    let map_len = match page_count_raw.checked_mul(4096) {
        Some(v) => v,
        None => return EINVAL,
    };
    let (virt_start, old_heap_end) = match crate::task::with_process_mut(pid, |process| {
        let base = if process.heap_end() < 0x7200_0000_0000u64 {
            0x7200_0000_0000u64
        } else {
            process.heap_end()
        };
        let virt_start = base
            .checked_add(0xfff)
            .map(|v| v & !0xfffu64)
            .ok_or(EINVAL)?;
        let new_heap_end = virt_start.checked_add(map_len).ok_or(EINVAL)?;
        let old_heap_end = process.heap_end();
        process.set_heap_end(new_heap_end);
        Ok((virt_start, old_heap_end))
    }) {
        Some(Ok(v)) => v,
        Some(Err(errno)) => return errno,
        None => return ENOMEM,
    };
    let rollback =
        |mapped| rollback_shared_pages(pid, pt_phys, virt_start, map_len, old_heap_end, mapped);

    let mut mapped = 0usize;
    for index in 0..page_count {
        let frame = match crate::mem::frame::allocate_zeroed_frame() {
            Ok(frame) => frame,
            Err(_) => {
                rollback(mapped);
                return ENOMEM;
            }
        };
        let phys = frame.start_address().as_u64();
        let virt = virt_start + (index as u64) * 4096;
        if crate::mem::paging::map_page_in_table(pt_phys, virt, phys, true, true).is_err() {
            let _ = crate::mem::frame::deallocate_frame(frame);
            rollback(mapped);
            return ENOMEM;
        }
        mapped += 1;
    }

    let region = crate::task::MemoryRegion::anonymous(
        virt_start,
        map_len,
        mnu_abi::MEMORY_ACCESS_READ | mnu_abi::MEMORY_ACCESS_WRITE,
        mnu_abi::MEMORY_MAP_SHARED,
        true,
        true,
    );
    let registered =
        crate::task::with_process_mut(pid, |process| process.add_memory_region(region))
            .unwrap_or(false);
    if !registered {
        rollback(mapped);
        return ENOMEM;
    }

    if phys_pages_ptr != 0 {
        for index in 0..page_count {
            let output = match phys_pages_ptr.checked_add((index as u64) * 8) {
                Some(output) => output,
                None => {
                    rollback(mapped);
                    return EFAULT;
                }
            };
            let virt = virt_start + (index as u64) * 4096;
            let phys = match crate::mem::paging::translate_addr_in_table(
                pt_phys,
                x86_64::VirtAddr::new(virt),
            ) {
                Some((phys, _)) => phys.as_u64() & !0xfff,
                None => {
                    rollback(mapped);
                    return EFAULT;
                }
            };
            if let Err(errno) = super::copy_to_user(output, &phys.to_ne_bytes()) {
                rollback(mapped);
                return errno;
            }
        }
    }
    virt_start
}

fn rollback_shared_pages(
    pid: crate::task::ProcessId,
    pt_phys: u64,
    virt_start: u64,
    map_len: u64,
    old_heap_end: u64,
    mapped: usize,
) {
    if mapped != 0 {
        let _ =
            crate::mem::paging::unmap_range_in_table(pt_phys, virt_start, (mapped as u64) * 4096);
    }
    let _ = crate::task::with_process_mut(pid, |process| {
        process.remove_memory_region(virt_start, map_len);
        if process.heap_end() >= virt_start {
            process.set_heap_end(old_heap_end);
        }
    });
}

/// memory_sync システムコール
///
/// 共有マッピングの内容を backing に同期する。
pub fn memory_sync(addr: u64, length: u64, options: u64) -> u64 {
    if options != 0 || addr == 0 || length == 0 || addr & 4095 != 0 {
        return EINVAL;
    }
    let sync_len = match page_align_up(length) {
        Some(v) if v > 0 => v,
        _ => return EINVAL,
    };
    if !is_user_range(addr, sync_len) {
        return EINVAL;
    }
    let pid = match crate::syscall::security::current_process_id() {
        Some(p) => p,
        None => return ENOSYS,
    };
    // Snapshot owned backing references while validating the entire range.
    // Provider IPC must not execute under the process-table lock. A concurrent
    // unmap/remap cannot redirect this operation to a different backing.
    let work = match crate::task::with_process(pid, |process| {
        crate::mem::range_plan::collect(addr, sync_len, |cursor| {
            let region = process.find_memory_region(cursor)?;
            let end = region.end()?;
            let backing = if region.is_shared() && region.permits_access(mnu_abi::MEMORY_ACCESS_WRITE)
            {
                match region.backing().file_object() {
                    Some(object) => {
                        let offset = region
                            .backing()
                            .file_offset()
                            .checked_add(cursor - region.start())?;
                        Some((Arc::clone(object), offset))
                    }
                    None => None,
                }
            } else {
                None
            };
            Some((end, backing))
        })
    }) {
        Some(Some(work)) => work,
        _ => return ENOMEM,
    };
    for ((object, offset), length) in work {
        if let Err(errno) = object.flush_range(offset, length) {
            return errno;
        }
    }
    // Do not clear virtual-region dirty state after I/O: the mapping may have
    // been replaced, and writable frames still require cache dirty tracking.
    SUCCESS
}

fn fill_random_buffer(buf_ptr: u64, len: u64) -> u64 {
    const CHUNK_LEN: usize = 256;
    if len == 0 {
        return 0;
    }
    if buf_ptr == 0 || len > isize::MAX as u64 || !super::validate_user_ptr(buf_ptr, len) {
        return EFAULT;
    }
    let mut buffer = [0u8; CHUNK_LEN];
    let mut offset = 0u64;
    while offset < len {
        let chunk_len = core::cmp::min(CHUNK_LEN as u64, len - offset) as usize;
        if crate::random::fill(&mut buffer[..chunk_len]).is_err() {
            buffer.fill(0);
            return EAGAIN;
        }
        if let Err(error) = crate::syscall::copy_to_user(buf_ptr + offset, &buffer[..chunk_len]) {
            buffer.fill(0);
            return error;
        }
        offset += chunk_len as u64;
    }
    buffer.fill(0);
    len
}

pub fn random_fill(buf_ptr: u64, len: u64) -> u64 {
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::SystemRandomRead,
    ]) {
        return super::types::EACCES;
    }
    fill_random_buffer(buf_ptr, len)
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
/// 見つかった場合は世代付きIPC endpoint handle、見つからない場合は0
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

    thread_id
        .and_then(crate::syscall::ipc::ensure_endpoint_handle_for_thread)
        .unwrap_or(0)
}
