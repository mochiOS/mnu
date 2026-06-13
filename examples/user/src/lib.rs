#![no_std]

use core::arch::asm;

pub mod fs_service;

pub const SYS_PROCESS_EXIT: u64 = mnu_abi::SyscallNumber::ProcessExit as u64;
pub const SYS_PROCESS_SPAWN: u64 = mnu_abi::SyscallNumber::ProcessSpawn as u64;
pub const SYS_PROCESS_WAIT: u64 = mnu_abi::SyscallNumber::ProcessWait as u64;
pub const SYS_THREAD_CREATE: u64 = mnu_abi::SyscallNumber::ThreadCreate as u64;
pub const SYS_THREAD_EXIT: u64 = mnu_abi::SyscallNumber::ThreadExit as u64;
pub const SYS_THREAD_YIELD: u64 = mnu_abi::SyscallNumber::ThreadYield as u64;
pub const SYS_MEMORY_ALLOC: u64 = mnu_abi::SyscallNumber::MemoryAlloc as u64;
pub const SYS_MEMORY_FREE: u64 = mnu_abi::SyscallNumber::MemoryFree as u64;
pub const SYS_MEMORY_MAP: u64 = mnu_abi::SyscallNumber::MemoryMap as u64;
pub const SYS_MEMORY_UNMAP: u64 = mnu_abi::SyscallNumber::MemoryUnmap as u64;
pub const SYS_MEMORY_PROTECT: u64 = mnu_abi::SyscallNumber::MemoryProtect as u64;
pub const SYS_MEMORY_SHARE: u64 = mnu_abi::SyscallNumber::MemoryShare as u64;
pub const SYS_MEMORY_SYNC: u64 = mnu_abi::SyscallNumber::MemorySync as u64;
pub const SYS_IPC_CREATE: u64 = mnu_abi::SyscallNumber::IpcCreate as u64;
pub const SYS_IPC_SEND: u64 = mnu_abi::SyscallNumber::IpcSend as u64;
pub const SYS_IPC_RECV: u64 = mnu_abi::SyscallNumber::IpcRecv as u64;
pub const SYS_IPC_CALL: u64 = mnu_abi::SyscallNumber::IpcCall as u64;
pub const SYS_IPC_REPLY: u64 = mnu_abi::SyscallNumber::IpcReply as u64;
pub const SYS_IPC_WAIT: u64 = mnu_abi::SyscallNumber::IpcWait as u64;
pub const SYS_CAP_CLONE: u64 = mnu_abi::SyscallNumber::CapClone as u64;
pub const SYS_CAP_DROP: u64 = mnu_abi::SyscallNumber::CapDrop as u64;
pub const SYS_CAP_TRANSFER: u64 = mnu_abi::SyscallNumber::CapTransfer as u64;
pub const SYS_CAP_QUERY: u64 = mnu_abi::SyscallNumber::CapQuery as u64;
pub const SYS_CAP_RESTRICT: u64 = mnu_abi::SyscallNumber::CapRestrict as u64;
pub const SYS_EVENT_CREATE: u64 = mnu_abi::SyscallNumber::EventCreate as u64;
pub const SYS_EVENT_WAIT: u64 = mnu_abi::SyscallNumber::EventWait as u64;
pub const SYS_EVENT_SIGNAL: u64 = mnu_abi::SyscallNumber::EventSignal as u64;
pub const SYS_EVENT_POLL: u64 = mnu_abi::SyscallNumber::EventPoll as u64;
pub const SYS_TIME_NOW: u64 = mnu_abi::SyscallNumber::TimeNow as u64;
pub const SYS_SLEEP: u64 = mnu_abi::SyscallNumber::Sleep as u64;
pub const SYS_CHECK_GRAVITY_EXIST: u64 = mnu_abi::SyscallNumber::CheckGravityExist as u64;
pub const SYS_WRITE: u64 = mnu_abi::SyscallNumber::Write as u64;
pub const SYS_SERVICE_SPAWN: u64 = mnu_abi::SyscallNumber::ServiceSpawn as u64;
pub const SYS_ALLOC_SHARED_PAGES: u64 = mnu_abi::SyscallNumber::AllocSharedPages as u64;
pub const SYS_IPC_SEND_PAGES: u64 = mnu_abi::SyscallNumber::IpcSendPages as u64;

#[inline(always)]
unsafe fn syscall0(n: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall1(n: u64, a0: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a0,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall2(n: u64, a0: u64, a1: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a0,
            in("rsi") a1,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall3(n: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall4(n: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall5(n: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8") a4,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

pub fn process_exit(code: u64) -> ! {
    unsafe {
        let _ = syscall1(SYS_PROCESS_EXIT, code);
    }
    loop {
        unsafe { asm!("pause", options(nomem, nostack, preserves_flags)); }
    }
}

pub fn process_spawn(_flags: u64, _reserved: u64) -> u64 {
    unsafe { syscall2(SYS_PROCESS_SPAWN, _flags, _reserved) }
}

pub fn service_spawn(path_ptr: u64) -> u64 {
    unsafe { syscall1(SYS_SERVICE_SPAWN, path_ptr) }
}

pub fn process_wait(pid: u64, status_ptr: u64, options: u64) -> u64 {
    unsafe { syscall3(SYS_PROCESS_WAIT, pid, status_ptr, options) }
}

pub fn thread_create(_entry: u64, _stack: u64, _arg: u64) -> u64 {
    unsafe { syscall3(SYS_THREAD_CREATE, _entry, _stack, _arg) }
}

pub fn thread_exit(code: u64) -> u64 {
    unsafe { syscall1(SYS_THREAD_EXIT, code) }
}

pub fn thread_yield() -> u64 {
    unsafe { syscall0(SYS_THREAD_YIELD) }
}

pub fn yield_now() -> u64 {
    thread_yield()
}

pub fn time_now() -> u64 {
    unsafe { syscall0(SYS_TIME_NOW) }
}

pub fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!(
            "lfence",
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | lo as u64
}

pub fn sleep(milliseconds: u64) -> u64 {
    unsafe { syscall1(SYS_SLEEP, milliseconds) }
}

pub fn check_gravity_exist() -> u64 {
    unsafe { syscall0(SYS_CHECK_GRAVITY_EXIST) }
}

pub fn write(fd: u64, buf_ptr: u64, len: u64) -> u64 {
    unsafe { syscall3(SYS_WRITE, fd, buf_ptr, len) }
}

pub fn alloc_shared_pages(
    page_count: u64,
    phys_addrs_out: u64,
    phys_addrs_len: u64,
    virt_addr_hint: u64,
) -> u64 {
    unsafe { syscall4(SYS_ALLOC_SHARED_PAGES, page_count, phys_addrs_out, phys_addrs_len, virt_addr_hint) }
}

pub fn ipc_send_pages(endpoint: u64, phys_pages_ptr: u64, page_count: u64, map_start: u64) -> u64 {
    unsafe { syscall4(SYS_IPC_SEND_PAGES, endpoint, phys_pages_ptr, page_count, map_start) }
}

pub fn ipc_create(flags: u64) -> u64 {
    unsafe { syscall2(SYS_IPC_CREATE, flags, 0) }
}

pub fn ipc_send(endpoint: u64, buf_ptr: u64, len: u64) -> u64 {
    unsafe { syscall3(SYS_IPC_SEND, endpoint, buf_ptr, len) }
}

pub fn ipc_recv(buf_ptr: u64, max_len: u64) -> u64 {
    unsafe { syscall2(SYS_IPC_RECV, buf_ptr, max_len) }
}

pub fn ipc_call(endpoint: u64, req_ptr: u64, req_len: u64, reply_ptr: u64, reply_len: u64) -> u64 {
    unsafe { syscall5(SYS_IPC_CALL, endpoint, req_ptr, req_len, reply_ptr, reply_len) }
}

pub fn ipc_reply(endpoint: u64, reply_ptr: u64, reply_len: u64) -> u64 {
    unsafe { syscall3(SYS_IPC_REPLY, endpoint, reply_ptr, reply_len) }
}

pub fn ipc_wait(buf_ptr: u64, max_len: u64, mode: u64) -> u64 {
    unsafe { syscall3(SYS_IPC_WAIT, buf_ptr, max_len, mode) }
}

pub fn memory_alloc(length: u64) -> u64 {
    unsafe { syscall1(SYS_MEMORY_ALLOC, length) }
}

pub fn memory_free(addr: u64, length: u64) -> u64 {
    unsafe { syscall2(SYS_MEMORY_FREE, addr, length) }
}

pub fn memory_map(addr: u64, length: u64, prot: u64, flags: u64, fd: u64) -> u64 {
    unsafe { syscall5(SYS_MEMORY_MAP, addr, length, prot, flags, fd) }
}

pub fn memory_unmap(addr: u64, length: u64) -> u64 {
    unsafe { syscall2(SYS_MEMORY_UNMAP, addr, length) }
}

pub fn memory_protect(addr: u64, length: u64, prot: u64) -> u64 {
    unsafe { syscall3(SYS_MEMORY_PROTECT, addr, length, prot) }
}

pub fn memory_share(_addr: u64, _length: u64, _flags: u64) -> u64 {
    unsafe { syscall3(SYS_MEMORY_SHARE, _addr, _length, _flags) }
}

pub fn memory_sync(_addr: u64, _length: u64, _flags: u64) -> u64 {
    unsafe { syscall3(SYS_MEMORY_SYNC, _addr, _length, _flags) }
}

pub fn cap_clone(cap_ptr: u64, cap_len: u64) -> u64 {
    unsafe { syscall2(SYS_CAP_CLONE, cap_ptr, cap_len) }
}

pub fn cap_drop(cap_ptr: u64, cap_len: u64) -> u64 {
    unsafe { syscall2(SYS_CAP_DROP, cap_ptr, cap_len) }
}

pub fn cap_transfer(dest: u64, cap_ptr: u64, cap_len: u64) -> u64 {
    unsafe { syscall3(SYS_CAP_TRANSFER, dest, cap_ptr, cap_len) }
}

pub fn cap_query(cap_ptr: u64, cap_len: u64) -> u64 {
    unsafe { syscall2(SYS_CAP_QUERY, cap_ptr, cap_len) }
}

pub fn cap_restrict(cap_ptr: u64, cap_len: u64, restriction_ptr: u64, restriction_len: u64) -> u64 {
    unsafe { syscall5(SYS_CAP_RESTRICT, cap_ptr, cap_len, restriction_ptr, restriction_len, 0) }
}

pub fn event_create(flags: u64) -> u64 {
    unsafe { syscall2(SYS_EVENT_CREATE, flags, 0) }
}

pub fn event_wait(event_id: u64, timeout_ms: u64) -> u64 {
    unsafe { syscall3(SYS_EVENT_WAIT, event_id, timeout_ms, 0) }
}

pub fn event_signal(event_id: u64) -> u64 {
    unsafe { syscall3(SYS_EVENT_SIGNAL, event_id, 0, 0) }
}

pub fn event_poll(event_ids_ptr: u64, count: u64, timeout_ms: u64) -> u64 {
    unsafe { syscall3(SYS_EVENT_POLL, event_ids_ptr, count, timeout_ms) }
}

pub fn run_self_test() -> bool {
    let gravity = check_gravity_exist();
    let t0 = time_now();
    let t1 = time_now();
    gravity == 0 && t1 >= t0
}

pub fn run_restricted_self_test() -> bool {
    run_self_test()
}
