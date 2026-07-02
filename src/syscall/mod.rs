//! システムコール

pub mod capability;
pub mod dma;
pub mod event;
pub mod exec;
pub mod fs;
pub mod io;
pub mod ipc;
pub mod pgroup;
pub mod process;
pub mod security;
pub mod signal;
pub mod syscall_entry;
pub mod task;
pub mod time;

mod console;
mod types;

use crate::capability::{KernelAuthority, KernelCapability, KernelObjectRef};
use alloc::string::String;
use alloc::vec::Vec;
use x86_64::instructions::port::Port;

/// ユーザー空間ポインタの有効性を検証する
///
/// ポインタが null でなく、ユーザー空間のアドレス範囲内にあること、
/// かつ `ptr + len` がオーバーフローしないことを確認する。
///
/// x86-64 canonical ユーザー空間上限: 0x0000_7FFF_FFFF_FFFF
pub fn validate_user_ptr(ptr: u64, len: u64) -> bool {
    if ptr == 0 {
        return false;
    }
    // x86-64 ユーザー空間の上限アドレス (canonical hole 下側)
    const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_FFFF;
    if ptr > USER_SPACE_END {
        return false;
    }
    let end_inclusive = if len == 0 {
        ptr
    } else {
        match ptr.checked_add(len - 1) {
            Some(e) => e,
            None => return false, // 整数オーバーフロー
        }
    };
    if end_inclusive > USER_SPACE_END {
        return false;
    }

    let user_pt = match crate::task::current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
        .and_then(|pid| crate::task::with_process(pid, |p| p.page_table()))
        .flatten()
    {
        Some(pt) => pt,
        None => return false,
    };

    crate::mem::paging::is_user_range_mapped_in_table(user_pt, ptr, len)
}

#[inline]
pub fn with_user_memory_access<R>(f: impl FnOnce() -> R) -> R {
    // Legacy no-op shim kept for old internal call sites outside the hardened
    // syscall copy path. New user-memory access must use copy_from_user/
    // copy_to_user so permission checks happen through the page-table walker.
    f()
}

fn current_user_page_table() -> Option<u64> {
    crate::task::current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
        .and_then(|pid| crate::task::with_process(pid, |p| p.page_table()))
        .flatten()
}

fn is_canonical_user_range(addr: u64, len: u64) -> bool {
    const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_FFFF;
    if addr == 0 || addr > USER_SPACE_END {
        return false;
    }
    let end_inclusive = if len == 0 {
        addr
    } else {
        match addr.checked_add(len - 1) {
            Some(end) => end,
            None => return false,
        }
    };
    end_inclusive <= USER_SPACE_END
}

/// ユーザー空間の null 終端文字列を最大長付きで読み取り、カーネル所有の `String` を返す。
pub fn read_user_cstring(ptr: u64, max_len: usize) -> Result<String, u64> {
    if ptr == 0 || max_len == 0 {
        return Err(EINVAL);
    }

    let mut bytes = Vec::with_capacity(max_len);
    for i in 0..max_len {
        let addr = ptr.checked_add(i as u64).ok_or(EFAULT)?;
        let mut one = [0u8; 1];
        copy_from_user(addr, &mut one)?;
        let b = one[0];
        if b == 0 {
            return String::from_utf8(bytes).map_err(|_| EINVAL);
        }
        bytes.push(b);
    }
    Err(EINVAL)
}

pub fn service_delegate_register(kind_raw: u64, pid_raw: u64) -> u64 {
    use crate::capability::Capability;
    use crate::policy::SpawnDelegateKind;
    use crate::syscall::types::{EACCES, EINVAL, ESRCH, SUCCESS};

    let caller_pid = match crate::task::current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
    {
        Some(pid) => pid,
        None => return EACCES,
    };
    let manager_pid = crate::policy::service_manager_pid();
    let is_manager = manager_pid != 0 && caller_pid.as_u64() == manager_pid;
    let can_register =
        crate::syscall::security::caller_has_any_capability(&[Capability::ServiceRegister]);
    if !is_manager && !can_register {
        return EACCES;
    }

    let kind = match kind_raw {
        1 => SpawnDelegateKind::Service,
        2 => SpawnDelegateKind::Driver,
        _ => return EINVAL,
    };

    let pid = crate::task::ProcessId::from_u64(pid_raw);
    let valid = crate::task::with_process(pid, |p| {
        let state = p.state();
        let alive = state != crate::task::ProcessState::Zombie
            && state != crate::task::ProcessState::Terminated;
        let privileged = matches!(
            p.privilege(),
            crate::task::PrivilegeLevel::Service | crate::task::PrivilegeLevel::Core
        );
        alive && privileged
    })
    .unwrap_or(false);
    if !valid {
        return ESRCH;
    }

    crate::policy::register_spawn_delegate(kind, pid_raw);
    SUCCESS
}

pub fn map_physical_range(virt_addr: u64, phys_addr: u64, size: u64) -> u64 {
    use crate::syscall::types::{EACCES, EINVAL, ENOMEM, EPERM, SUCCESS};
    if virt_addr == 0
        || size == 0
        || (virt_addr & 0xfff) != 0
        || (phys_addr & 0xfff) != 0
        || (size & 0xfff) != 0
    {
        return EINVAL;
    }
    if !is_canonical_user_range(virt_addr, size) {
        return EINVAL;
    }
    if !crate::mem::frame::is_allowed_mmio_range(phys_addr, size) {
        crate::audit::log(
            crate::audit::AuditEventKind::Policy,
            "MapPhysicalRange rejected non-MMIO or allocator-owned physical range",
        );
        return EPERM;
    }

    let pid = match crate::syscall::security::current_process_id() {
        Some(pid) => pid,
        None => return ENOMEM,
    };
    let requested_authority = KernelAuthority::new(
        KernelCapability::PhysMap,
        KernelObjectRef::MmioRegion {
            base: phys_addr,
            size,
        },
    );
    if !crate::task::process_has_kernel_authority(pid, &requested_authority) {
        return EACCES;
    }
    let pt_phys = match crate::task::with_process(pid, |proc| proc.page_table()).flatten() {
        Some(pt) => pt,
        None => return ENOMEM,
    };

    let writable = true;
    let mapping = crate::task::MmioMapping::new(virt_addr, size, phys_addr, writable);
    let admitted = crate::task::with_process_mut(pid, |proc| {
        if proc.mmio_mapping_count() >= proc.resource_limits().max_mmio_ranges {
            return Err(ENOMEM);
        }
        if !proc.add_mmio_mapping(mapping.clone()) {
            return Err(EINVAL);
        }
        Ok(())
    });
    match admitted {
        Some(Ok(())) => {}
        Some(Err(errno)) => return errno,
        None => return ENOMEM,
    }

    if crate::mem::paging::map_physical_range_to_user(pt_phys, virt_addr, phys_addr, size).is_err()
    {
        let _ = crate::mem::paging::unmap_range_in_table_preserve_frames(pt_phys, virt_addr, size);
        let _ =
            crate::task::with_process_mut(pid, |proc| proc.remove_mmio_mapping(virt_addr, size));
        return ENOMEM;
    }

    SUCCESS
}

pub fn get_physical_addr(virt_addr: u64) -> u64 {
    use crate::capability::Capability;
    use crate::syscall::types::{EACCES, EFAULT, ENOMEM};

    if !crate::syscall::security::caller_has_any_capability(&[Capability::MemoryPhysTranslate]) {
        return EACCES;
    }
    if !validate_user_ptr(virt_addr, 1) {
        return EFAULT;
    }
    let pt_phys = match current_user_page_table() {
        Some(pt) => pt,
        None => return ENOMEM,
    };
    crate::mem::paging::virt_to_phys_in_table(pt_phys, virt_addr).unwrap_or(EFAULT)
}

fn debug_serial_write_str(s: &str) {
    unsafe {
        // SAFETY: COM1 is the conventional debug serial port in this kernel,
        // and this helper is used only for temporary debugging without locks.
        let mut data = Port::<u8>::new(0x3F8);
        let mut line_status = Port::<u8>::new(0x3F8 + 5);
        for byte in s.bytes() {
            while line_status.read() & 0x20 == 0 {}
            data.write(byte);
        }
    }
}

/// ユーザー空間からバイト列をコピーする（コピー先はカーネル空間）。
pub fn copy_from_user(src_ptr: u64, dst: &mut [u8]) -> Result<(), u64> {
    if dst.is_empty() {
        return Ok(());
    }
    let user_pt = match current_user_page_table() {
        Some(pt) => pt,
        None => return Err(EFAULT),
    };
    if src_ptr == 0 {
        return Err(EFAULT);
    }
    crate::mem::paging::copy_from_user_in_table(user_pt, src_ptr, dst).map_err(|err| {
        crate::audit::log(
            crate::audit::AuditEventKind::Usercopy,
            "copy_from_user rejected unmapped or unreadable range",
        );
        match err {
            crate::Kernel::Memory(crate::result::Memory::OutOfMemory) => EFAULT,
            crate::Kernel::Memory(crate::result::Memory::PermissionDenied) => EFAULT,
            crate::Kernel::Memory(crate::result::Memory::InvalidAddress) => EFAULT,
            _ => EFAULT,
        }
    })
}

/// バイト列をユーザー空間へコピーする（コピー元はカーネル空間）。
pub fn copy_to_user(dst_ptr: u64, src: &[u8]) -> Result<(), u64> {
    if src.is_empty() {
        return Ok(());
    }
    let user_pt = match current_user_page_table() {
        Some(pt) => pt,
        None => return Err(EFAULT),
    };
    if dst_ptr == 0 {
        return Err(EFAULT);
    }
    crate::mem::paging::copy_to_user_in_table(user_pt, dst_ptr, src).map_err(|err| {
        crate::audit::log(
            crate::audit::AuditEventKind::Usercopy,
            "copy_to_user rejected unmapped or unwritable range",
        );
        match err {
            crate::Kernel::Memory(crate::result::Memory::OutOfMemory) => EFAULT,
            crate::Kernel::Memory(crate::result::Memory::PermissionDenied) => EFAULT,
            crate::Kernel::Memory(crate::result::Memory::InvalidAddress) => EFAULT,
            _ => EFAULT,
        }
    })
}

pub fn read_user_u64(ptr: u64) -> Result<u64, u64> {
    let mut buf = [0u8; 8];
    copy_from_user(ptr, &mut buf)?;
    Ok(u64::from_ne_bytes(buf))
}

pub fn read_user_u32(ptr: u64) -> Result<u32, u64> {
    let mut buf = [0u8; 4];
    copy_from_user(ptr, &mut buf)?;
    Ok(u32::from_ne_bytes(buf))
}

pub fn read_user_i64(ptr: u64) -> Result<i64, u64> {
    let mut buf = [0u8; 8];
    copy_from_user(ptr, &mut buf)?;
    Ok(i64::from_ne_bytes(buf))
}

pub fn read_user_i32(ptr: u64) -> Result<i32, u64> {
    let mut buf = [0u8; 4];
    copy_from_user(ptr, &mut buf)?;
    Ok(i32::from_ne_bytes(buf))
}

pub fn read_user_u16(ptr: u64) -> Result<u16, u64> {
    let mut buf = [0u8; 2];
    copy_from_user(ptr, &mut buf)?;
    Ok(u16::from_ne_bytes(buf))
}

pub fn write_user_u64(ptr: u64, value: u64) -> Result<(), u64> {
    copy_to_user(ptr, &value.to_ne_bytes())
}

pub fn write_user_u32(ptr: u64, value: u32) -> Result<(), u64> {
    copy_to_user(ptr, &value.to_ne_bytes())
}

pub fn write_user_i32(ptr: u64, value: i32) -> Result<(), u64> {
    copy_to_user(ptr, &value.to_ne_bytes())
}

pub fn write_user_u16(ptr: u64, value: u16) -> Result<(), u64> {
    copy_to_user(ptr, &value.to_ne_bytes())
}

pub use types::*;

use crate::info;
use crate::syscall::syscall_entry::switch_to_current_thread_user_page_table;
use x86_64::structures::idt::InterruptStackFrame;

/// システムコールのディスパッチ
pub fn dispatch(num: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    match num {
        x if x == SyscallNumber::ProcessExit as u64 => process::exit(arg0),
        x if x == SyscallNumber::ProcessSpawn as u64 => process::spawn(arg0, arg1),
        x if x == SyscallNumber::ServiceSpawn as u64 => ENOSYS,
        x if x == SyscallNumber::ServiceDelegateRegister as u64 => {
            service_delegate_register(arg0, arg1)
        }
        x if x == SyscallNumber::DriverSpawn as u64 => ENOSYS,
        x if x == SyscallNumber::DmaAlloc as u64 => dma::alloc(arg0, arg1),
        x if x == SyscallNumber::DmaFree as u64 => dma::free(arg0),
        x if x == SyscallNumber::ExecManifest as u64 => {
            exec::exec_manifest_syscall(arg0, arg1, arg2, arg3, arg4)
        }
        x if x == SyscallNumber::ProcessWait as u64 => process::wait(arg0, arg1, arg2),
        x if x == SyscallNumber::ThreadCreate as u64 => task::thread_create(arg0, arg1, arg2),
        x if x == SyscallNumber::ThreadExit as u64 => {
            if let Some(id) = crate::task::current_thread_id() {
                crate::task::terminate_thread(id);
                SUCCESS
            } else {
                ENOSYS
            }
        }
        x if x == SyscallNumber::ThreadYield as u64 => {
            task::yield_now();
            SUCCESS
        }
        x if x == SyscallNumber::MemoryAlloc as u64 => process::mmap(0, arg0, arg1, arg2, arg3),
        x if x == SyscallNumber::MemoryFree as u64 => process::munmap(arg0, arg1),
        x if x == SyscallNumber::MemoryMap as u64 => process::mmap(arg0, arg1, arg2, arg3, arg4),
        x if x == SyscallNumber::MemoryUnmap as u64 => process::munmap(arg0, arg1),
        x if x == SyscallNumber::MemoryProtect as u64 => pgroup::mprotect(arg0, arg1, arg2),
        x if x == SyscallNumber::MemoryShare as u64 => process::memory_share(arg0, arg1, arg2),
        x if x == SyscallNumber::MemorySync as u64 => process::memory_sync(arg0, arg1, arg2),
        x if x == SyscallNumber::IpcCreate as u64 => ipc::create(arg0, arg1),
        x if x == SyscallNumber::IpcSend as u64 => ipc::send(arg0, arg1, arg2),
        x if x == SyscallNumber::IpcRecv as u64 => ipc::recv(arg0, arg1),
        x if x == SyscallNumber::IpcCall as u64 => ipc::call(arg0, arg1, arg2, arg3, arg4),
        x if x == SyscallNumber::IpcReply as u64 => ipc::reply(arg0, arg1, arg2),
        x if x == SyscallNumber::IpcWait as u64 => ipc::wait(arg0, arg1, arg2),
        x if x == SyscallNumber::CapClone as u64 => capability::clone_capability(arg0, arg1),
        x if x == SyscallNumber::CapDrop as u64 => capability::drop_capability(arg0, arg1),
        x if x == SyscallNumber::CapTransfer as u64 => {
            capability::transfer_capability(arg0, arg1, arg2)
        }
        x if x == SyscallNumber::CapQuery as u64 => capability::query(arg0, arg1),
        x if x == SyscallNumber::CapRestrict as u64 => {
            capability::restrict_capability(arg0, arg1, arg2, arg3)
        }
        x if x == SyscallNumber::EventCreate as u64 => event::create(arg0, arg1),
        x if x == SyscallNumber::EventWait as u64 => event::wait(arg0, arg1, arg2),
        x if x == SyscallNumber::EventSignal as u64 => event::signal(arg0, arg1, arg2),
        x if x == SyscallNumber::EventPoll as u64 => event::poll(arg0, arg1, arg2),
        x if x == SyscallNumber::TimeNow as u64 => time::get_ticks(),
        x if x == SyscallNumber::Sleep as u64 => process::sleep(arg0),
        x if x == SyscallNumber::Write as u64 => io::write(arg0, arg1, arg2),
        x if x == SyscallNumber::PortIn as u64 => io::port_in(arg0, arg1),
        x if x == SyscallNumber::PortOut as u64 => io::port_out(arg0, arg1, arg2),
        x if x == SyscallNumber::MapPhysicalRange as u64 => map_physical_range(arg0, arg1, arg2),
        x if x == SyscallNumber::VirtToPhys as u64 => get_physical_addr(arg0),
        x if x == SyscallNumber::GetPhysicalAddr as u64 => get_physical_addr(arg0),
        x if x == SyscallNumber::Execve as u64 => exec::execve_syscall(arg0, arg1, arg2),
        x if x == SyscallNumber::FileOpen as u64 => fs::file_open(arg0, arg1),
        x if x == SyscallNumber::FileOpenAt as u64 => {
            fs::file_open_at(arg0 as i64, arg1, arg2, arg3)
        }
        x if x == SyscallNumber::FileClose as u64 => fs::file_close(arg0),
        x if x == SyscallNumber::FileRead as u64 => fs::file_read(arg0, arg1, arg2),
        x if x == SyscallNumber::FileWrite as u64 => fs::file_write(arg0, arg1, arg2),
        x if x == SyscallNumber::FileSeek as u64 => fs::file_seek(arg0, arg1 as i64, arg2),
        x if x == SyscallNumber::FileStat as u64 => fs::file_stat(arg0, arg1),
        x if x == SyscallNumber::FileStatAt as u64 => {
            fs::file_stat_at(arg0 as i64, arg1, arg2, arg3)
        }
        x if x == SyscallNumber::FileFstat as u64 => fs::file_fstat(arg0, arg1),
        x if x == SyscallNumber::FileReadDir as u64 => fs::file_read_dir(arg0, arg1, arg2),
        x if x == SyscallNumber::FileCreateDir as u64 => fs::file_create_dir(arg0, arg1),
        x if x == SyscallNumber::FileRemove as u64 => fs::file_remove(arg0),
        x if x == SyscallNumber::FileRename as u64 => {
            fs::file_rename(arg0 as i64, arg1, arg2 as i64, arg3)
        }
        x if x == SyscallNumber::FileSync as u64 => fs::file_sync(arg0),
        x if x == SyscallNumber::Chdir as u64 => fs::chdir(arg0),
        x if x == SyscallNumber::Getcwd as u64 => fs::getcwd(arg0, arg1),
        _ => ENOSYS,
    }
}

/// fork/clone のみ、現在スレッドへユーザーコンテキストを保存する
#[no_mangle]
pub extern "sysv64" fn save_user_context_for_fork(
    num: u64,
    user_rip: u64,
    user_rsp: u64,
    user_rflags: u64,
) {
    crate::syscall::syscall_entry::verify_kernel_page_table_before_rust();
    let _ = num;
    if let Some(tid) = crate::task::current_thread_id() {
        let _ = crate::task::with_thread_mut(tid, |thread| {
            thread.set_syscall_user_context(user_rip, user_rsp, user_rflags);
        });
    }
}

/// システムコール割り込みハンドラ (int 0x80) - アセンブリラッパー
///
/// # Safety
/// CPU が int 0x80 入口規約どおりのスタック/レジスタ状態でこの関数へ入ることを前提とする。
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_interrupt_handler() {
    core::arch::naked_asm!(
        // すべてのレジスタを保存（システムコール引数を含む）
        "push rax",      // syscall number
        "push rcx",
        "push rdx",      // arg2
        "push rbx",
        "push rbp",
        "push rsi",      // arg1
        "push rdi",      // arg0
        "push r8",       // arg4
        "push r9",
        "push r10",      // arg3
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // カーネルデータセグメントをロード
        // （ds/esはスタックに保存しない。復元時にユーザーセグメントを再設定）
        "mov ax, 0x10",    // カーネルデータセグメント (index=2)
        "mov ds, ax",
        "mov es, ax",

        // int 0x80 経路は、kernel CR3 に切り替えたまま dispatch と signal return を完結させる。
        // KPTI で user CR3 から kernel heap を完全に外しているため、signal 配送や
        // プロセス/スレッド metadata 参照を user CR3 上で行うと kernel-mode page fault になる。
        "mov rdi, rsp",               // arg0 = kstack（saved registers 先頭）
        "call {int80_handler}",       // 最終的な戻り値を rax で返す

        // 戻り値 (rax) をスタック上の保存された rax の位置に書き込む
        "mov [rsp + 112], rax",

        // ユーザーデータセグメントを設定
        "mov ax, 0x1b",    // ユーザーデータセグメント (index=3, RPL=3)
        "mov ds, ax",
        "mov es, ax",

        // すべてのレジスタを復元
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rbp",
        "pop rbx",
        "pop rdx",
        "pop rcx",
        "pop rax",

        // 割り込みから戻る
        "iretq",

        int80_handler = sym syscall_interrupt_handler_rust,
    );
}

/// int 0x80 経路専用の Rust wrapper。
///
/// dispatch 本体だけでなく signal 配送/rt_sigreturn まで kernel CR3 上で完結させる。
/// これにより、KPTI で user CR3 から外した kernel heap / task metadata へ
/// user CR3 のまま触れてしまう事故を防ぐ。
extern "sysv64" fn syscall_interrupt_handler_rust(kstack: *mut u64) -> u64 {
    crate::percpu::install_current_cpu_gs_base();

    let prev_cr3 = syscall_entry::switch_to_kernel_page_table();
    crate::cpu::reassert_runtime_hardening();

    let syscall_num = unsafe { kstack.add(14).read() };

    let current_tid = crate::task::current_thread_id();
    let current_slot = crate::task::current_thread_slot();
    if let Some(slot) = current_slot {
        crate::task::with_thread_at_slot_mut(slot, |t| t.set_in_syscall(true));
    } else if let Some(tid) = current_tid {
        crate::task::with_thread_mut(tid, |t| t.set_in_syscall(true));
    }

    let ret = dispatch(
        syscall_num,
        unsafe { kstack.add(8).read() },  // saved rdi = arg0
        unsafe { kstack.add(9).read() },  // saved rsi = arg1
        unsafe { kstack.add(12).read() }, // saved rdx = arg2
        unsafe { kstack.add(5).read() },  // saved r10 = arg3
        unsafe { kstack.add(7).read() },  // saved r8  = arg4
    );

    if let Some(slot) = current_slot {
        crate::task::with_thread_at_slot_mut(slot, |t| t.set_in_syscall(false));
    } else if let Some(tid) = current_tid {
        crate::task::with_thread_mut(tid, |t| t.set_in_syscall(false));
    }

    let ret = signal::signal_and_return(kstack, ret);
    // int 0x80 復帰フレームの CS/SS を GDT 実値で正規化する。
    // 一部環境で固定値と実際の GDT 割当がずれると iretq で #GP(index=3/4) を起こすため、
    // 毎回ここで明示的に揃える。
    let user_cs = (crate::mem::gdt::user_code_selector() as u64) | 0x3;
    let user_ss = (crate::mem::gdt::user_data_selector() as u64) | 0x3;
    unsafe {
        kstack.add(16).write(user_cs);
        kstack.add(19).write(user_ss);
    }
    syscall_entry::restore_page_table(prev_cr3);
    ret
}

/// システムコールハンドラの Rust 実装
extern "C" fn syscall_handler_rust(
    num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
) -> u64 {
    crate::percpu::install_current_cpu_gs_base();

    let current_tid = crate::task::current_thread_id();
    let current_slot = crate::task::current_thread_slot();

    let _prev_cr3 = syscall_entry::switch_to_kernel_page_table();
    crate::cpu::reassert_runtime_hardening();

    if let Some(slot) = current_slot {
        crate::task::with_thread_at_slot_mut(slot, |t| t.set_in_syscall(true));
    } else if let Some(tid) = current_tid {
        crate::task::with_thread_mut(tid, |t| t.set_in_syscall(true));
    }

    let ret = dispatch(num, arg0, arg1, arg2, arg3, arg4);

    if let Some(slot) = current_slot {
        crate::task::with_thread_at_slot_mut(slot, |t| t.set_in_syscall(false));
    } else if let Some(tid) = current_tid {
        crate::task::with_thread_mut(tid, |t| t.set_in_syscall(false));
    }

    ret
}

#[no_mangle]
pub extern "sysv64" fn syscall_user_cr3_for_sysret() -> u64 {
    syscall_entry::current_thread_user_page_table().unwrap_or(0)
}

/// SYSCALL 命令エントリから呼ばれる system V ABI ディスパッチ関数
///
/// syscall_entry.rs の naked asm から `call {dispatch}` で呼ばれる。
/// system V ABI: 引数は rdi, rsi, rdx, rcx, r8, r9 の順。
#[no_mangle]
pub extern "sysv64" fn syscall_dispatch_sysv(
    num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
) -> u64 {
    syscall_handler_rust(num, arg0, arg1, arg2, arg3, arg4)
}
