//! プロセス管理関連のシステムコール

use super::types::{EAGAIN, EFAULT, EINVAL, ENOMEM, ENOSPC, ENOSYS, EPERM, ESRCH, SUCCESS};
use crate::task::ThreadId;
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
        let mut context = mnu_abi::ThreadSecurityContext::default();
        context.process_id = pid.as_u64();
        context.thread_id = thread_id;
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

    const RECORD_SIZE: usize = mnu_abi::PROCESS_INFO_RECORD_SIZE;
    if buf_ptr == 0 {
        return 0;
    }
    let max_bytes = buf_len as usize;
    let max_entries = max_bytes / RECORD_SIZE;
    if max_entries == 0 {
        return 0;
    }

    let mut thread_metrics: Vec<(crate::task::ProcessId, u64)> = Vec::new();
    crate::task::for_each_thread(|thread| {
        let process_id = thread.process_id();
        if let Some((_, count)) = thread_metrics
            .iter_mut()
            .find(|(candidate, _)| *candidate == process_id)
        {
            *count = count.saturating_add(1);
        } else {
            thread_metrics.push((process_id, 1));
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
        let thread_count = thread_metrics
            .iter()
            .find(|(process_id, _)| *process_id == proc.id())
            .map(|(_, count)| *count)
            .unwrap_or(0);
        let cpu_ticks = proc.process_object().cpu_ticks();
        out_buf[24..32].copy_from_slice(&cpu_ticks.to_ne_bytes());
        out_buf[32..40].copy_from_slice(&proc.mapped_memory_bytes().to_ne_bytes());
        out_buf[40..48].copy_from_slice(&thread_count.to_ne_bytes());
        // Signed applications expose their package identity. Other processes use
        // the explicit name supplied when they were created; the kernel does not
        // infer user-space roles from executable paths or filename conventions.
        let name = proc
            .application_identity()
            .map(|identity| identity.package_id())
            .unwrap_or_else(|| proc.name());
        // Name follows native metrics, with 56 bytes for UTF-8 identity.
        let name_bytes = name.as_bytes();
        let copy_len = core::cmp::min(RECORD_SIZE - 48, name_bytes.len());
        out_buf[48..48 + copy_len].copy_from_slice(&name_bytes[..copy_len]);
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

/// Creates a VM image, never a process, thread, or inherited authority table.
pub fn clone_address_space() -> u64 {
    use crate::mem::address_space::{CloneError, CloneSource};
    if !caller_has_process_spawn_capability() {
        return EPERM;
    }
    let Some(pid) = crate::syscall::security::current_process_id() else {
        return ENOSYS;
    };
    // Exclude in-flight construction and new admission through completion of
    // the image. A count sampled without this gate can miss a new runnable
    // thread published after the check but before COW capture.
    let Some(_capture) = crate::task::image_transition::begin_image_transition(pid) else {
        return EAGAIN;
    };
    let Some(owner) = crate::task::current_thread_id() else {
        return ENOSYS;
    };
    let _quiescence = crate::task::scheduler::quiesce_image_siblings(pid, owner);
    // CONTROL authorizes eventual image consumption; MAP/READ/WRITE do not
    // grant access to these pages through ordinary memory-object operations.
    let rights = crate::task::HandleRights::CONTROL
        .union(crate::task::HandleRights::DUPLICATE)
        .union(crate::task::HandleRights::TRANSFER);
    crate::task::with_process_mut(pid, |process| {
        // Capture, COW source-PTE edits and Handle publication share the VM
        // lock with faults/unmap/resize. Do not expose a detached source table
        // to a concurrent backing revocation between capture and cloning.
        let source = match CloneSource::capture(process) {
            Ok(source) => source,
            Err(CloneError::BorrowedMapping) => return EPERM,
            Err(CloneError::BackingBusy) => return EAGAIN,
            Err(CloneError::Allocation) => return ENOMEM,
            Err(_) => return ENOSYS,
        };
        let cloned = source.clone_image();
        // Failed cloning may also have write-protected some source PTEs.
        // Retain every image/frame reference until remote invalidation ends.
        if crate::mem::tlb_shootdown::invalidate_all().is_err() {
            return crate::syscall::EIO;
        }
        let image = match cloned {
            Ok(image) => Arc::new(crate::mem::address_space::AddressSpaceObject::new(image)),
            Err(_) => return ENOMEM,
        };
        process
            .object_handles_mut()
            .insert(crate::task::ObjectHandleEntry::new(
                crate::task::KernelObject::AddressSpace(image),
                rights,
            ))
            .map(|handle| handle.raw() as u64)
            .unwrap_or(ENOSPC)
    })
    .unwrap_or(ENOSYS)
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

/// Resolve a write-authorized COW leaf in the caller's retained VM root.
pub(crate) fn resolve_user_copy_on_write(table: u64, address: u64) -> crate::result::Result<bool> {
    let pid = crate::syscall::security::current_process_id()
        .ok_or(crate::Kernel::Memory(crate::result::Memory::InvalidAddress))?;
    crate::task::with_process_mut(pid, |process| {
        if process.page_table() != Some(table) {
            return Err(crate::Kernel::Memory(crate::result::Memory::InvalidAddress));
        }
        // Serialize COW leaf edits with native protection, unmap and teardown.
        crate::mem::mapping_admission::check_access(process.memory_regions(), address, 1)?;
        crate::mem::paging::resolve_copy_on_write(table, address)
    })
    .unwrap_or(Err(crate::Kernel::Memory(crate::result::Memory::InvalidAddress)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MemoryFault {
    Unmapped,
    AccessDenied,
    Backing(crate::mem::vm_object::VmPageError),
    Operation(u64),
}

impl From<u64> for MemoryFault {
    fn from(error: u64) -> Self {
        Self::Operation(error)
    }
}

impl MemoryFault {
    /// A backing reservation or superseded page snapshot is not a user access
    /// violation. Retry outside all VM/cache locks rather than deliver an upcall.
    pub(crate) fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Operation(EAGAIN)
                | Self::Backing(crate::mem::vm_object::VmPageError::Operation(EAGAIN))
        )
    }

    pub(crate) fn cause(self) -> mnu_abi::MemoryFaultCause {
        use crate::mem::vm_object::VmPageError;
        use mnu_abi::MemoryFaultCause;
        match self {
            Self::Unmapped => MemoryFaultCause::Unmapped,
            Self::AccessDenied => MemoryFaultCause::AccessDenied,
            Self::Backing(VmPageError::OutsideBacking) => MemoryFaultCause::OutsideBacking,
            Self::Operation(ENOMEM) | Self::Backing(VmPageError::Operation(ENOMEM)) => {
                MemoryFaultCause::ResourceUnavailable
            }
            Self::Backing(VmPageError::Operation(_)) => MemoryFaultCause::BackingFailure,
            Self::Operation(_) => MemoryFaultCause::Unresolved,
        }
    }
}

/// Resolves one page, retaining the cause at the failing operation rather
/// than guessing from a second lookup of potentially changed VM metadata.
pub(crate) fn handle_user_memory_fault(
    fault_addr: u64,
    is_write: bool,
    is_execute: bool,
) -> Result<(), MemoryFault> {
    let tid = match current_thread_id() {
        Some(t) => t,
        None => return Err(MemoryFault::Operation(ESRCH)),
    };
    let pid = match crate::task::with_thread(tid, |t| t.process_id()) {
        Some(p) => p,
        None => return Err(MemoryFault::Operation(ESRCH)),
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
            None => return Err(MemoryFault::Operation(EINVAL)),
        };
        let region = match process.find_memory_region_mut(fault_addr) {
            Some(region) => region,
            None => {
                crate::debug!("[MEMORY_FAULT] no region for {:#x}", fault_addr);
                return Err(MemoryFault::Unmapped);
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
            return Err(MemoryFault::AccessDenied);
        }
        if is_write && !region.allows_write_at(fault_addr) {
            crate::debug!("[MEMORY_FAULT] write fault on read-only mapping");
            return Err(MemoryFault::AccessDenied);
        }
        if is_execute && !region.allows_execute_at(fault_addr) {
            crate::debug!("[MEMORY_FAULT] instruction fault on non-executable mapping");
            return Err(MemoryFault::AccessDenied);
        }
        if crate::mem::paging::is_user_range_mapped_in_table(pt_phys, page_addr, 1) {
            if !is_write {
                crate::debug!("[MEMORY_FAULT] page already mapped {:#x}", page_addr);
                return Err(MemoryFault::Operation(EINVAL));
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
                return Err(MemoryFault::Operation(ENOMEM));
            }
            region.mark_dirty_page((page_addr - region.start()) / 4096);
            crate::debug!("[MEMORY_FAULT] upgraded dirty page {:#x}", page_addr);
            return Ok(true);
        }
        Ok(false)
    });
    match resident {
        Some(Ok(true)) => return Ok(()),
        Some(Ok(false)) => {}
        Some(Err(error)) => return Err(error),
        None => return Err(MemoryFault::Operation(ESRCH)),
    }

    let plan = crate::task::with_process(pid, |process| {
        let pt_phys = process.page_table().ok_or(EINVAL)?;
        let region = process.find_memory_region(fault_addr).ok_or(MemoryFault::Unmapped)?;
        if !region.allows_read_at(fault_addr)
            || (is_write && !region.allows_write_at(fault_addr))
            || (is_execute && !region.allows_execute_at(fault_addr))
        {
            return Err(MemoryFault::AccessDenied);
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
        let generation = pager
            .as_ref()
            .and_then(|(object, _)| object.memory_generation());
        Ok((
            pt_phys,
            region.start(),
            shared_file,
            pager,
            generation,
        ))
    });
    let (pt_phys, region_start, shared_file, pager, generation) =
        plan.ok_or(MemoryFault::Operation(ESRCH))??;

    let page = match pager.as_ref() {
        Some((object, page_index)) if !shared_file => match object.page(*page_index) {
            Ok(page) => Some(page),
            Err(error) => {
                return if object.memory_generation() != generation {
                    Ok(())
                } else {
                    Err(MemoryFault::Backing(error))
                };
            }
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
            Err(error) => return Err(MemoryFault::Backing(error)),
        },
        _ => None,
    };

    let result = crate::task::with_process_mut(pid, |process| {
        if process.page_table() != Some(pt_phys) {
            return Err(MemoryFault::Operation(EINVAL));
        }
        let region = process.find_memory_region_mut(fault_addr).ok_or(MemoryFault::Unmapped)?;
        if region.start() != region_start
            || !region.allows_read_at(fault_addr)
            || (is_write && !region.allows_write_at(fault_addr))
            || (is_execute && !region.allows_execute_at(fault_addr))
        {
            return Err(MemoryFault::AccessDenied);
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
            return Err(MemoryFault::Operation(EINVAL));
        }
        let executable = region.allows_execute_at(fault_addr);
        if crate::mem::paging::is_user_range_mapped_in_table(pt_phys, page_addr, 1) {
            return Ok(());
        }
        if shared_file {
            let Some((object, page_index)) = pager.as_ref() else {
                return Err(MemoryFault::Operation(EINVAL));
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
                    return Err(MemoryFault::Operation(ENOMEM));
                }
            }
        } else {
            let page = page.as_ref().ok_or(EINVAL)?;
            let install = || {
                crate::mem::paging::map_and_copy_segment_to(
                    pt_phys,
                    page_addr,
                    crate::mem::vm_object::PAGE_BYTES as u64,
                    4096,
                    page.as_slice(),
                    is_write && region.allows_write_at(fault_addr),
                    executable,
                )
                .map_err(|_| ENOMEM)
            };
            match pager.as_ref() {
                Some((object, _)) => object.with_memory_generation(generation, install)?,
                None => install()?,
            }
        }
        if is_write {
            region.mark_dirty_page((page_addr - region.start()) / 4096);
        }
        crate::debug!("[MEMORY_FAULT] mapped page {:#x}", page_addr);
        Ok(())
    });

    // A backing resize invalidated the prepared page. Retry the instruction
    // and fault again to prepare current backing; never install the stale pin.
    match result {
        Some(Ok(())) | Some(Err(MemoryFault::Operation(EAGAIN))) => Ok(()),
        Some(Err(error)) => Err(error),
        None => Err(MemoryFault::Operation(ESRCH)),
    }
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
    memory_map_impl(
        addr,
        length,
        access,
        options,
        backing_handle,
        backing_offset,
        None,
    )
}

pub fn memory_map_bounded(request: u64, request_len: u64) -> u64 {
    if request_len != mnu_abi::memory_map::REQUEST_LEN as u64 {
        return EINVAL;
    }
    let mut bytes = [0; mnu_abi::memory_map::REQUEST_LEN];
    // Copy before PROCESS_TABLE: the source may itself need a user fault.
    if crate::syscall::copy_from_user(request, &mut bytes).is_err() {
        return EFAULT;
    }
    let Some(request) = mnu_abi::memory_map::Request::decode(&bytes) else {
        return EINVAL;
    };
    memory_map_impl(
        request.address,
        request.length,
        request.access,
        request.options,
        request.backing_handle,
        request.backing_offset,
        Some(request.byte_ceiling),
    )
}

fn memory_map_impl(
    addr: u64,
    length: u64,
    access: u64,
    options: u64,
    backing_handle: u64,
    backing_offset: u64,
    byte_ceiling: Option<u64>,
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
    let replace = options & mnu_abi::MEMORY_MAP_REPLACE != 0;
    let shared = options & mnu_abi::MEMORY_MAP_SHARED != 0;
    if replace && !exact {
        return EINVAL;
    }
    if exact && (addr == 0 || addr & 4095 != 0) {
        return EINVAL;
    }

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
    if !anonymous && backing_offset.checked_add(size).is_none() {
        return EINVAL;
    }

    let writable = access & mnu_abi::MEMORY_ACCESS_WRITE != 0;
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
            crate::task::KernelObject::Provider(provider) => {
                let identity = match crate::syscall::handle::provider_memory_object(&provider) {
                    Ok(identity) => identity,
                    Err(error) => return error,
                };
                let object = match crate::mem::vm_object::VmObject::provider(provider, identity) {
                    Ok(object) => object,
                    Err(error) => return error,
                };
                match Arc::try_new(object) {
                    Ok(object) => object,
                    Err(_) => return ENOMEM,
                }
            }
            crate::task::KernelObject::VmObject(object) => {
                if object.memory_identity().is_none() {
                    return EINVAL;
                }
                // Reserve virtual space independently of the current extent.
                // A resizable object can populate it later. RAM page faults
                // enforce the live extent and generation before installing a
                // PTE; reserving a range grants no access to absent storage.
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
        // Choose a placement cursor without publishing changes on failure.
        let placement_base = if process.heap_start() == 0 {
            let exec_cfg = crate::config::kernel().exec;
            let default_heap_base = randomized_heap_base(
                pid,
                exec_cfg.memory_map_base_min,
                exec_cfg.memory_map_aslr_max_pages,
            );
            default_heap_base
        } else {
            process.heap_end()
        };

        // ユーザー空間の上限アドレスを超えるaddrを拒否
        if addr != 0 && addr > USER_SPACE_END {
            return Err(EINVAL);
        }

        let pt_phys = match process.page_table() {
            Some(p) => p,
            None => return Err(ENOMEM),
        };

        if let Some(ceiling) = byte_ceiling.filter(|&value| value != u64::MAX && !replace) {
            use crate::mem::mapping_usage;
            // PROCESS_TABLE retains the root and excludes every mapping/PTE
            // writer. Do not use heap_end: it is a placement cursor, not use.
            let used = mapping_usage::bytes(
                process
                    .memory_regions()
                    .iter()
                    .map(|region| (region.start(), region.end().unwrap_or(u64::MAX)))
                    .chain(process.mmio_mappings().iter().map(|mapping| {
                        (mapping.virt_start(), mapping.end().unwrap_or(u64::MAX))
                    }))
                    .chain(process.dma_buffers().iter().map(|buffer| {
                        (buffer.virt_start(), buffer.end().unwrap_or(u64::MAX))
                    })),
                |start, end| unsafe {
                    crate::mem::paging::next_user_page_entry(pt_phys, start, end)
                },
            )
            .map_err(|_| EFAULT)?;
            if !mapping_usage::permits(used, size, ceiling) {
                return Err(ENOMEM);
            }
        }

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
            if !is_user_range(candidate, size) || (!replace && !range_is_available(candidate)) {
                return Err(EINVAL);
            }
            candidate
        } else if requested.is_some_and(range_is_available) {
            requested.unwrap_or(0)
        } else {
            let mut candidate = match page_align_up(placement_base) {
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

        let region = if anonymous {
            // Shared reservations retain one backing object across clones,
            // including pages neither process has faulted yet. Its storage
            // is populated lazily by the existing RAM-object pager.
            if shared {
                let memory = Arc::try_new(crate::mem::shared_memory::SharedMemory::new(
                    size, size / 4096,
                )?).map_err(|_| ENOMEM)?;
                let object = Arc::try_new(crate::mem::vm_object::VmObject::shared_memory(memory))
                    .map_err(|_| ENOMEM)?;
                crate::task::MemoryRegion::file_backed(
                    map_start, size, access, options, object, 0, writable, true,
                    mnu_abi::MEMORY_ACCESS_ALL,
                )
            } else {
                crate::task::MemoryRegion::anonymous(
                    map_start, size, access, options, writable, false,
                )
            }
            // Both private and shared reservations use zero-fill faults;
            // access permissions never force eager physical allocation.
        } else {
            let (object, file_offset, max_access) = match file_backing {
                Some(backing) => backing,
                None => return Err(EINVAL),
            };
            // Reservations and new mapping admission share PROCESS_TABLE.
            // Do not publish metadata for a backing being changed by its owner.
            object.with_memory_generation(object.memory_generation(), || Ok(()))?;
            crate::task::MemoryRegion::file_backed(
                map_start,
                size,
                access,
                options,
                object,
                file_offset,
                writable,
                shared,
                max_access,
            )
        };
        let removed = if replace {
            crate::mem::mapping_replace::replace(process, region, byte_ceiling)
                .map_err(mnu_abi::status::Error::into_raw)?
        } else {
            if !process.add_memory_region(region) {
                return Err(EINVAL);
            }
            Vec::new()
        };

        if process.heap_start() == 0 {
            process.set_heap_start(placement_base);
            process.set_heap_end(placement_base);
        }
        // heap_end を更新してアドレス空間が重ならないようにする
        if !exact {
            let new_heap_end = match map_start.checked_add(size) {
                Some(v) => v,
                None => return Err(EINVAL),
            };
            process.set_heap_end(new_heap_end);
        }

        Ok((map_start, removed))
    });

    match result {
        Some(Ok((va, removed))) => {
            // Reuse the unmap writeback contract, outside PROCESS_TABLE. The
            // removed slices retain their original backing and offsets; an
            // overlapping new mapping never redirects this cleanup.
            for region in removed {
                if region.is_shared() && region.permits_access(mnu_abi::MEMORY_ACCESS_WRITE) {
                    if let Some(object) = region.backing().file_object() {
                        if let Err(error) = object.flush_unmapped_range(
                            region.backing().file_offset(), region.len(),
                        ) {
                            return error;
                        }
                    }
                }
            }
            va
        }
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
    let outcome = crate::task::with_process_mut(pid, |process| {
        use crate::mem::{mapping_revocation as transaction, mapping_revocation_native::Native};
        let table = process.page_table().ok_or(ENOSYS)?;
        if process
            .find_dma_buffer_by_addr(unmap_start, unmap_len)
            .is_some()
        {
            return Err(EPERM);
        }
        let mmio = process.find_mmio_mapping_by_addr(unmap_start, unmap_len);
        if let Some(mapping) = mmio {
            if mapping.virt_start() != unmap_start || mapping.len() != unmap_len {
                return Err(EINVAL);
            }
        }
        let owns_frames = mmio.is_none();
        crate::mem::mapping_admission::check_unmap(
            process.memory_regions(),
            unmap_start,
            unmap_end,
        )
        .map_err(mnu_abi::status::Error::into_raw)?;
        let metadata = if owns_frames {
            Some(
                process
                    .prepare_remove_memory_range(unmap_start, unmap_len)
                    .map_err(|error| match error {
                        crate::task::process::MemoryRangeError::InvalidRange => EINVAL,
                        crate::task::process::MemoryRangeError::Allocation => ENOMEM,
                    })?,
            )
        } else {
            None
        };
        // SAFETY: PROCESS_TABLE stays locked across all PTE edits and remote
        // acknowledgements. A fault cannot reinstall a suspended page here.
        let mut backend = unsafe { Native::for_process(process, owns_frames) };
        transaction::revoke([(table, unmap_start, unmap_end)], &mut backend)
            .map_err(|error| match error {
                transaction::Error::InvalidRange => EINVAL,
                transaction::Error::Allocation => ENOMEM,
                transaction::Error::Backend(error) => error.into_raw(),
            })?;
        // Metadata is committed only after successful revocation. Failure
        // restores PTEs and leaves the original ranges/frame ownership intact.
        if let Some((retained, removed)) = metadata {
            process.set_memory_regions(retained);
            Ok(removed)
        } else {
            process.remove_mmio_mapping(unmap_start, unmap_len);
            Ok(Vec::new())
        }
    });
    let removed = match outcome {
        Some(Ok(removed)) => removed,
        Some(Err(error)) => return error,
        None => return ENOSYS,
    };
    // Provider writeback may do IPC: never perform it under PROCESS_TABLE.
    for region in removed {
        if region.is_shared() && region.permits_access(mnu_abi::MEMORY_ACCESS_WRITE) {
            if let Some(object) = region.backing().file_object() {
                if let Err(errno) =
                    object.flush_unmapped_range(region.backing().file_offset(), region.len())
                {
                    return errno;
                }
            }
        }
    }
    SUCCESS
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
    use mnu_abi::status::Error;
    const CHUNK_LEN: usize = 256;
    if len == 0 {
        return 0;
    }
    if len > isize::MAX as u64 {
        return Error::LimitExceeded.into_raw();
    }
    if buf_ptr == 0 || !super::validate_user_ptr(buf_ptr, len) {
        return Error::InvalidAddress.into_raw();
    }
    let mut buffer = [0u8; CHUNK_LEN];
    let mut offset = 0u64;
    while offset < len {
        let chunk_len = core::cmp::min(CHUNK_LEN as u64, len - offset) as usize;
        if crate::random::fill(&mut buffer[..chunk_len]).is_err() {
            buffer.fill(0);
            return Error::NotReady.into_raw();
        }
        if let Err(error) = crate::syscall::copy_to_user_native(
            buf_ptr + offset,
            &buffer[..chunk_len],
        ) {
            buffer.fill(0);
            return error.into_raw();
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
        return mnu_abi::status::Error::AccessDenied.into_raw();
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
