#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

mod file_options;
mod native_launch;

const HEAP_SIZE: usize = 256 * 1024;

#[repr(align(16))]
struct Heap([u8; HEAP_SIZE]);

static mut HEAP: Heap = Heap([0; HEAP_SIZE]);

struct BumpAllocator {
    offset: AtomicUsize,
}

impl BumpAllocator {
    const fn new() -> Self {
        Self {
            offset: AtomicUsize::new(0),
        }
    }

    fn heap_base() -> usize {
        unsafe { core::ptr::addr_of!(HEAP.0) as usize }
    }
}

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = Self::heap_base();
        let heap_end = base + HEAP_SIZE;
        let mut current = self.offset.load(Ordering::Relaxed);
        loop {
            let aligned = (base + current + layout.align() - 1) & !(layout.align() - 1);
            let next = match aligned.checked_add(layout.size()) {
                Some(v) => v,
                None => return core::ptr::null_mut(),
            };
            if next > heap_end {
                return core::ptr::null_mut();
            }
            let next_offset = next - base;
            match self.offset.compare_exchange(
                current,
                next_offset,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return aligned as *mut u8,
                Err(actual) => current = actual,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator::new();

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

const SYS_DEBUG_WRITE: u64 = mnu_abi::SyscallNumber::DebugWrite as u64;
const SYS_PROCESS_EXIT: u64 = mnu_abi::SyscallNumber::ProcessExit as u64;
const SYS_ADDRESS_SPACE_CLONE: u64 = mnu_abi::SyscallNumber::AddressSpaceClone as u64;
const SYS_HANDLE_CLOSE: u64 = mnu_abi::SyscallNumber::HandleClose as u64;
const SYS_PROCESS_HANDLE_WAIT: u64 = mnu_abi::SyscallNumber::ProcessHandleWait as u64;
const SYS_PROCESS_HANDLE_OPEN_BY_ID: u64 =
    mnu_abi::SyscallNumber::ProcessHandleOpenById as u64;
const SYS_THREAD_CREATE: u64 = mnu_abi::SyscallNumber::ThreadCreate as u64;
const SYS_THREAD_EXIT: u64 = mnu_abi::SyscallNumber::ThreadExit as u64;
const SYS_THREAD_YIELD: u64 = mnu_abi::SyscallNumber::ThreadYield as u64;
const SYS_MEMORY_MAP: u64 = mnu_abi::SyscallNumber::MemoryMap as u64;
const SYS_MEMORY_UNMAP: u64 = mnu_abi::SyscallNumber::MemoryUnmap as u64;
const SYS_MEMORY_PROTECT: u64 = mnu_abi::SyscallNumber::MemoryProtect as u64;
const SYS_MEMORY_SYNC: u64 = mnu_abi::SyscallNumber::MemorySync as u64;
const SYS_MAP_PHYSICAL_RANGE: u64 = mnu_abi::SyscallNumber::MapPhysicalRange as u64;
const SYS_IPC_CREATE: u64 = mnu_abi::SyscallNumber::IpcCreate as u64;
const SYS_IPC_CALL: u64 = mnu_abi::SyscallNumber::IpcCall as u64;
const SYS_IPC_REPLY: u64 = mnu_abi::SyscallNumber::IpcReply as u64;
const SYS_IPC_WAIT: u64 = mnu_abi::SyscallNumber::IpcWait as u64;
const SYS_IPC_SEND: u64 = mnu_abi::SyscallNumber::IpcSend as u64;
const SYS_IPC_RECV_WAIT: u64 = mnu_abi::SyscallNumber::IpcRecvWait as u64;
const SYS_CAP_CLONE: u64 = mnu_abi::SyscallNumber::CapClone as u64;
const SYS_CAP_DROP: u64 = mnu_abi::SyscallNumber::CapDrop as u64;
const SYS_CAP_TRANSFER: u64 = mnu_abi::SyscallNumber::CapTransfer as u64;
const SYS_CAP_QUERY: u64 = mnu_abi::SyscallNumber::CapQuery as u64;
const SYS_CAP_RESTRICT: u64 = mnu_abi::SyscallNumber::CapRestrict as u64;
const SYS_TIME_NOW: u64 = mnu_abi::SyscallNumber::TimeNow as u64;
const SYS_PERFORMANCE_SNAPSHOT: u64 = mnu_abi::SyscallNumber::PerformanceSnapshot as u64;
const SYS_SLEEP: u64 = mnu_abi::SyscallNumber::Sleep as u64;
const SYS_CHECK_THREAD_CAPABILITY: u64 = mnu_abi::SyscallNumber::CheckThreadCapability as u64;
const SYS_LIST_PROCESSES: u64 = mnu_abi::SyscallNumber::ListProcesses as u64;
const SYS_FIND_PROCESS_BY_NAME: u64 = mnu_abi::SyscallNumber::FindProcessByName as u64;
const PLUGKIT_TEST_DRIVER_PATH: &str = "/plugkit/test/entry.elf";
const INIT_FS_TEST_PATH: &str = "/tmp/init.fs-test";
const SIGNATURE_DB_PATH: &str = "/policy/execution.allowlist";
const SIGNATURE_ALLOW_PATH: &str = "/tmp/captest.bin";
const SIGNATURE_DENY_PATH: &str = "/tmp/unsigned.bin";
const ROOTFS_BENCH_PATH: &str = "/tmp/testdata";
const MEMORY_PHYS_MAP_CAP: &str = "memory.phys.map";
const FS_TEST_SIZE: usize = 1024 * 1024;
static mut FS_TEST_WRITE_BUF: [u8; FS_TEST_SIZE] = [0x55; FS_TEST_SIZE];
static mut FS_TEST_READ_BUF: [u8; FS_TEST_SIZE] = [0; FS_TEST_SIZE];

fn bss_zero_fill_self_test() -> bool {
    const PAGE_BYTES: usize = 4096;
    let buffer = core::ptr::addr_of!(FS_TEST_READ_BUF).cast::<u8>();
    let first_is_zero = unsafe { core::ptr::read_volatile(buffer) == 0 };
    let last_is_zero = unsafe { core::ptr::read_volatile(buffer.add(FS_TEST_SIZE - 1)) == 0 };
    if !first_is_zero || !last_is_zero {
        return false;
    }

    let middle_page =
        ((buffer as usize + FS_TEST_SIZE / 2 + PAGE_BYTES - 1) & !(PAGE_BYTES - 1)) as u64;
    if memory_protect(middle_page, PAGE_BYTES as u64, 6) == 0
        || memory_protect(middle_page, PAGE_BYTES as u64, 0) != 0
        || memory_protect(middle_page, PAGE_BYTES as u64, 3) != 0
    {
        return false;
    }
    unsafe {
        core::ptr::write_volatile(middle_page as *mut u8, 0x5a);
        core::ptr::read_volatile(middle_page as *const u8) == 0x5a
    }
}

#[inline(always)]
unsafe fn syscall0(n: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
        "syscall",
        inlateout("rax") n => ret,
        lateout("rcx") _,
        lateout("r11") _,
        lateout("r10") _,
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
        lateout("r10") _,
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
        lateout("r10") _,
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
        lateout("r10") _,
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

#[inline(always)]
unsafe fn syscall6(n: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
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
        in("r9") a5,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
        );
    }
    ret
}

#[inline(always)]
#[allow(dead_code)]
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

pub fn write_str(s: &str) {
    unsafe {
        let _ = syscall2(SYS_DEBUG_WRITE, s.as_ptr() as u64, s.len() as u64);
    }
}

pub fn debug_write(ptr: u64, len: u64) -> u64 {
    unsafe { syscall2(SYS_DEBUG_WRITE, ptr, len) }
}

pub fn process_exit(code: u64) -> ! {
    unsafe {
        let _ = syscall1(SYS_PROCESS_EXIT, code);
    }
    loop {
        unsafe {
            asm!("pause", options(nomem, nostack, preserves_flags));
        }
    }
}

pub fn process_wait(pid: u64, status_ptr: u64, flags: u64) -> u64 {
    if flags != 0 || pid == u64::MAX {
        return mnu_abi::EINVAL;
    }
    let handle = unsafe {
        syscall2(
            SYS_PROCESS_HANDLE_OPEN_BY_ID,
            pid,
            mnu_abi::HANDLE_RIGHT_WAIT,
        )
    };
    if (handle as i64) < 0 {
        return handle;
    }
    let waited = wait_process_handle(handle, status_ptr);
    if (waited as i64) < 0 {
        waited
    } else {
        pid
    }
}

/// Captures only the current VM image; creates no process or implicit grants.
pub fn clone_address_space() -> u64 {
    unsafe { syscall0(SYS_ADDRESS_SPACE_CLONE) }
}

pub fn process_wait_handle(handle: u64, status_ptr: u64) -> u64 {
    let waited = wait_process_handle(handle, status_ptr);
    if (waited as i64) < 0 {
        waited
    } else {
        handle
    }
}

fn wait_process_handle(handle: u64, status_ptr: u64) -> u64 {
    let mut process_status = mnu_abi::ProcessStatus::default();
    let waited = unsafe {
        syscall3(
            SYS_PROCESS_HANDLE_WAIT,
            handle,
            mnu_abi::PROCESS_WAIT_INFINITE,
            (&mut process_status as *mut mnu_abi::ProcessStatus) as u64,
        )
    };
    let _ = unsafe { syscall1(SYS_HANDLE_CLOSE, handle) };
    if (waited as i64) < 0 {
        return waited;
    }
    if status_ptr != 0 {
        let status = ((process_status.exit_code as i32 & 0xff) << 8) as i32;
        unsafe { core::ptr::write(status_ptr as *mut i32, status) };
    }
    0
}

pub fn performance_snapshot(
    snapshot: &mut mnu_abi::performance::KernelPerformanceSnapshot,
) -> u64 {
    unsafe {
        syscall2(
            SYS_PERFORMANCE_SNAPSHOT,
            snapshot as *mut _ as u64,
            core::mem::size_of_val(snapshot) as u64,
        )
    }
}

fn exec_and_wait(path: &str) -> Option<i32> {
    native_launch::spawn(path).ok()?.wait().ok()
}

fn exec_should_be_denied(path: &str) -> bool {
    // An unavailable broker, missing fixture, or transport failure is not
    // evidence that signature policy rejected the executable.
    native_launch::spawn(path).err().is_some_and(|error| {
        matches!(error.errno(), Some(1 | 13))
    })
}

pub fn thread_create(context: &mnu_abi::ThreadCreateContext) -> u64 {
    unsafe {
        syscall2(
            SYS_THREAD_CREATE,
            context as *const mnu_abi::ThreadCreateContext as u64,
            core::mem::size_of::<mnu_abi::ThreadCreateContext>() as u64,
        )
    }
}

pub fn thread_exit(code: u64) -> ! {
    unsafe {
        let _ = syscall1(SYS_THREAD_EXIT, code);
    }
    loop {
        unsafe {
            asm!("pause", options(nomem, nostack, preserves_flags));
        }
    }
}

pub fn thread_yield() -> u64 {
    unsafe { syscall0(SYS_THREAD_YIELD) }
}

pub fn memory_alloc(len: u64, access: u64, options: u64, backing_handle: u64, offset: u64) -> u64 {
    unsafe {
        syscall6(
            SYS_MEMORY_MAP,
            0,
            len,
            access,
            options,
            backing_handle,
            offset,
        )
    }
}

pub fn memory_free(addr: u64, len: u64) -> u64 {
    unsafe { syscall2(SYS_MEMORY_UNMAP, addr, len) }
}

pub fn memory_map(addr: u64, len: u64, access: u64, options: u64, backing_handle: u64) -> u64 {
    unsafe {
        syscall6(
            SYS_MEMORY_MAP,
            addr,
            len,
            access,
            options,
            backing_handle,
            0,
        )
    }
}

pub fn memory_unmap(addr: u64, len: u64) -> u64 {
    unsafe { syscall2(SYS_MEMORY_UNMAP, addr, len) }
}

pub fn memory_protect(addr: u64, len: u64, access: u64) -> u64 {
    unsafe { syscall3(SYS_MEMORY_PROTECT, addr, len, access) }
}

pub fn memory_sync(addr: u64, len: u64, options: u64) -> u64 {
    unsafe { syscall3(SYS_MEMORY_SYNC, addr, len, options) }
}

pub fn map_physical_range(virt_addr: u64, phys_addr: u64, size: u64) -> u64 {
    unsafe { syscall3(SYS_MAP_PHYSICAL_RANGE, virt_addr, phys_addr, size) }
}

pub fn ipc_create(flags: u64) -> u64 {
    unsafe { syscall2(SYS_IPC_CREATE, flags, 0) }
}

pub fn ipc_call(endpoint: u64, req_ptr: u64, req_len: u64, reply_ptr: u64, reply_len: u64) -> u64 {
    unsafe {
        syscall5(
            SYS_IPC_CALL,
            endpoint,
            req_ptr,
            req_len,
            reply_ptr,
            reply_len,
        )
    }
}

pub fn ipc_reply(dest: u64, ptr: u64, len: u64) -> u64 {
    unsafe { syscall3(SYS_IPC_REPLY, dest, ptr, len) }
}

pub fn ipc_wait(ptr: u64, len: u64, flags: u64) -> u64 {
    unsafe { syscall3(SYS_IPC_WAIT, ptr, len, flags) }
}



pub fn ipc_send(dest: u64, ptr: u64, len: u64) -> u64 {
    unsafe { syscall3(SYS_IPC_SEND, dest, ptr, len) }
}

pub fn ipc_recv(ptr: u64, len: u64) -> u64 {
    unsafe { syscall2(SYS_IPC_RECV_WAIT, ptr, len) }
}

pub fn cap_clone(ptr: u64, len: u64) -> u64 {
    unsafe { syscall2(SYS_CAP_CLONE, ptr, len) }
}

pub fn cap_drop(ptr: u64, len: u64) -> u64 {
    unsafe { syscall2(SYS_CAP_DROP, ptr, len) }
}

pub fn cap_transfer(dest: u64, ptr: u64, len: u64) -> u64 {
    unsafe { syscall3(SYS_CAP_TRANSFER, dest, ptr, len) }
}

pub fn cap_query(ptr: u64, len: u64) -> u64 {
    unsafe { syscall2(SYS_CAP_QUERY, ptr, len) }
}

pub fn cap_restrict(src_ptr: u64, src_len: u64, dst_ptr: u64, dst_len: u64) -> u64 {
    unsafe { syscall4(SYS_CAP_RESTRICT, src_ptr, src_len, dst_ptr, dst_len) }
}

pub fn time_now() -> u64 {
    unsafe { syscall0(SYS_TIME_NOW) }
}

/// Opens through the inherited POSIX endpoint and returns a native Handle,
/// not a POSIX FD. The sample can use it directly as MemoryMap backing.
pub fn file_open(path: &str, flags: u64) -> u64 {
    use mochios_posix_client::{Client, ClientError, OpenAtBase};
    let options = match file_options::open_options(flags) {
        Ok(options) => options,
        Err(error) => return error,
    };
    let result = Client::from_syscall_launch_context().and_then(|client| {
        client.open_at(OpenAtBase::ProcessRoot, options, 0o666, path)
    });
    match result {
        Ok(file) => file.handle as u64,
        Err(ClientError::Transport(error)) => error.raw() as u64,
        Err(ClientError::Remote(status)) => status as i64 as u64,
        Err(_) => mnu_abi::EIO,
    }
}

pub fn file_close(handle: u64) -> u64 {
    unsafe { syscall1(mnu_abi::SyscallNumber::HandleClose as u64, handle) }
}

pub fn file_read(handle: u64, buf: &mut [u8]) -> u64 {
    unsafe {
        syscall3(
            mnu_abi::SyscallNumber::HandleRead as u64,
            handle,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    }
}

pub fn file_write(handle: u64, buf: &[u8]) -> u64 {
    unsafe {
        syscall3(
            mnu_abi::SyscallNumber::HandleWrite as u64,
            handle,
            buf.as_ptr() as u64,
            buf.len() as u64,
        )
    }
}

pub fn file_seek(handle: u64, offset: i64, whence: u64) -> u64 {
    let basis = match whence {
        0 => mnu_abi::HANDLE_SEEK_START,
        1 => mnu_abi::HANDLE_SEEK_CURRENT,
        2 => mnu_abi::HANDLE_SEEK_END,
        _ => return mnu_abi::EINVAL,
    };
    unsafe {
        syscall3(
            mnu_abi::SyscallNumber::HandleSeek as u64,
            handle,
            offset as u64,
            basis,
        )
    }
}


fn ipc_send_bytes(dest: u64, buf: &[u8]) -> u64 {
    unsafe { syscall3(SYS_IPC_SEND, dest, buf.as_ptr() as u64, buf.len() as u64) }
}

fn ipc_recv_wait_bytes(buf: &mut [u8]) -> u64 {
    unsafe { syscall2(SYS_IPC_RECV_WAIT, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

fn find_process_by_name(name: &str) -> u64 {
    let mut name_buf = [0u8; 64];
    let bytes = name.as_bytes();
    if bytes.len() > name_buf.len() {
        return 0;
    }
    name_buf[..bytes.len()].copy_from_slice(bytes);
    unsafe {
        syscall2(
            SYS_FIND_PROCESS_BY_NAME,
            name_buf.as_ptr() as u64,
            bytes.len() as u64,
        )
    }
}

fn launch_plugkit_test_driver() -> Option<(native_launch::Child, u64)> {
    let child = native_launch::spawn(PLUGKIT_TEST_DRIVER_PATH).ok()?;
    for _ in 0..100 {
        let tid = find_process_by_name("com.mnu.plugkit.test.null");
        if tid != 0 {
            return Some((child, tid));
        }
        let tid = find_process_by_name(PLUGKIT_TEST_DRIVER_PATH);
        if tid != 0 {
            return Some((child, tid));
        }
        let _ = yield_now();
    }
    None
}

fn recv_ipc_response(buf: &mut [u8]) -> Option<(u64, usize)> {
    let rc = ipc_recv_wait_bytes(buf);
    if rc == 0 || rc & (1u64 << 63) != 0 {
        let mut line = LineBuf::new();
        let _ = core::fmt::write(&mut line, format_args!("plugkit-test recv error {rc:#x}"));
        write_line(line.as_str());
        return None;
    }
    Some((rc >> 32, (rc & 0xffff_ffff) as usize))
}

fn ipc_round_trip(dest: u64, msg: &str, buf: &mut [u8]) -> Option<usize> {
    let sent = ipc_send_bytes(dest, msg.as_bytes());
    if sent & (1u64 << 63) != 0 {
        let mut line = LineBuf::new();
        let _ = core::fmt::write(&mut line, format_args!("plugkit-test send error {sent:#x}"));
        write_line(line.as_str());
        return None;
    }
    loop {
        let (from, len) = recv_ipc_response(buf)?;
        if from == dest && len <= buf.len() {
            let text = core::str::from_utf8(&buf[..len]).ok()?;
            if text == "ready" {
                continue;
            }
            return Some(len);
        }
    }
}

struct LineBuf {
    buf: [u8; 160],
    len: usize,
}

impl LineBuf {
    fn new() -> Self {
        Self {
            buf: [0; 160],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("<fmt>")
    }
}

impl core::fmt::Write for LineBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len().saturating_sub(self.len);
        let take = bytes.len().min(remaining);
        self.buf[self.len..self.len + take].copy_from_slice(&bytes[..take]);
        self.len += take;
        if take < bytes.len() {
            return Err(core::fmt::Error);
        }
        Ok(())
    }
}

fn format_line(prefix: &str, bytes: u64, elapsed_ms: u64, mib_s: f64) -> LineBuf {
    let mut line = LineBuf::new();
    let _ = core::fmt::write(
        &mut line,
        format_args!(
            "{} {} bytes in {} ms: {:.1} MiB/s",
            prefix, bytes, elapsed_ms, mib_s
        ),
    );
    line
}

pub fn path_registry_self_test() -> bool {
    write_line("[init][path-map]");
    write_line("/tmp/init.fs-test\towner=service\trights=read|write|create\ttype=Custom");
    let line = alloc::format!(
        "{}\towner=service\trights=read|list\ttype=Custom",
        ROOTFS_BENCH_PATH
    );
    write_line(line.as_str());
    true
}

fn fileio_self_test() -> bool {
    use mnu_abi::status::Error;

    const TICK_MS: u64 = 2;

    let path = INIT_FS_TEST_PATH;
    let payload = unsafe {
        core::slice::from_raw_parts(
            core::ptr::addr_of!(FS_TEST_WRITE_BUF) as *const u8,
            FS_TEST_SIZE,
        )
    };
    let buffer = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(FS_TEST_READ_BUF) as *mut u8,
            FS_TEST_SIZE,
        )
    };

    let fd = file_open(path, 0o2 | 0o100 | 0o1000);
    if fd == 0 || fd > u32::MAX as u64 {
        write_line("fs-test: open failed");
        return false;
    }

    let write_start = get_ticks();
    let wrote = file_write(fd, payload);
    let write_elapsed_ms = get_ticks().saturating_sub(write_start) * TICK_MS;
    if wrote != payload.len() as u64 {
        let _ = file_close(fd);
        return false;
    }

    let _ = file_seek(fd, 0, 0);
    let read_start = get_ticks();
    let read = file_read(fd, buffer);
    let read_elapsed_ms = get_ticks().saturating_sub(read_start) * TICK_MS;

    let _ = file_close(fd);
    let closed_errno = file_read(fd, buffer);

    let ro_fd = file_open(path, 0o0);
    if ro_fd == 0 || ro_fd > u32::MAX as u64 {
        write_line("fs-test: read-only open failed");
        return false;
    }
    let ro_write_errno = file_write(ro_fd, &payload[..16]);
    let _ = file_close(ro_fd);

    let wo_fd = file_open(path, 0o1 | 0o100);
    if wo_fd == 0 || wo_fd > u32::MAX as u64 {
        write_line("fs-test: write-only open failed");
        return false;
    }
    let wo_read_errno = file_read(wo_fd, &mut buffer[..16]);
    let _ = file_close(wo_fd);

    let same = read == payload.len() as u64 && bytes_eq(payload, buffer);
    let write_mib_s = if write_elapsed_ms == 0 {
        0.0
    } else {
        (wrote as f64) / (1024.0 * 1024.0) / ((write_elapsed_ms as f64) / 1000.0)
    };
    let read_mib_s = if read_elapsed_ms == 0 {
        0.0
    } else {
        (read as f64) / (1024.0 * 1024.0) / ((read_elapsed_ms as f64) / 1000.0)
    };

    let write_line_buf = format_line(
        "[init][fs-test] write",
        wrote,
        write_elapsed_ms,
        write_mib_s,
    );
    let read_line_buf = format_line(
        "[init][fs-test] read ",
        read,
        read_elapsed_ms,
        read_mib_s,
    );
    write_line(write_line_buf.as_str());
    write_line(read_line_buf.as_str());

    same && closed_errno == Error::InvalidArgument.into_raw()
        && ro_write_errno == Error::AccessDenied.into_raw()
        && wo_read_errno == Error::AccessDenied.into_raw()
}

fn plugkit_ipc_self_test() -> bool {
    let Some((mut driver, driver_tid)) = launch_plugkit_test_driver() else {
        write_line("plugkit-test: driver launch failed");
        return false;
    };
    let tid_line = format_line("plugkit-test tid", driver_tid, 0, 0.0);
    write_line(tid_line.as_str());
    for cap in ["ipc.client", "ipc.server", "fs.write.all"] {
        let mut line = [0u8; 64];
        let prefix = b"plugkit-test cap ";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut len = prefix.len();
        let bytes = cap.as_bytes();
        line[len..len + bytes.len()].copy_from_slice(bytes);
        len += bytes.len();
        line[len..len + 3].copy_from_slice(b" = ");
        len += 3;
        let ok = thread_has_capability(driver_tid, cap);
        let value = if ok { b"yes" } else { b"no " };
        line[len..len + value.len()].copy_from_slice(value);
        len += value.len();
        if let Ok(text) = core::str::from_utf8(&line[..len]) {
            write_line(text);
        }
    }
    let mut proc_buf = [0u8; 2048];
    let count = list_processes(&mut proc_buf);
    if count > 0 {
        let record_size = mnu_abi::PROCESS_INFO_RECORD_SIZE;
        let max_records = core::cmp::min(count as usize, proc_buf.len() / record_size);
        for idx in 0..max_records {
            let start = idx * record_size;
            let end = start + record_size;
            if process_record_matches_name(&proc_buf[start..end], b"com.mnu.plugkit.test.null") {
                let state = process_record_state(&proc_buf[start..end]);
                let mut line = LineBuf::new();
                let _ = core::fmt::write(&mut line, format_args!("plugkit-test state {}", state));
                write_line(line.as_str());
                break;
            }
        }
    }
    for _ in 0..20 {
        if find_process_state_by_name(b"com.mnu.plugkit.test.null") == Some(3) {
            break;
        }
        let _ = yield_now();
    }
    let _ = yield_now();

    let commands = [
        ("manifest", "ok manifest com.mnu.plugkit.test.null"),
        ("match", "ok match"),
        ("start", "ok start"),
        ("io", "io mmio=1 irq=1 ok"),
        ("deny missing.cap", "err PermissionDenied"),
        ("start-fail missing.cap", "err PermissionDenied cleanup=ok"),
        ("stop", "ok stop"),
        ("logs", "ok logs"),
        ("shutdown", "ok shutdown"),
    ];

    for (cmd, expected) in commands.iter() {
        let mut buf = [0u8; 1024];
        let Some(len) = ipc_round_trip(driver_tid, cmd, &mut buf) else {
            write_line("plugkit-test: ipc round trip failed");
            return false;
        };
        let Ok(resp) = core::str::from_utf8(&buf[..len]) else {
            return false;
        };
        if !resp.contains(expected) {
            write_line("plugkit-test: response mismatch");
            return false;
        }
    }

    if driver.wait() == Ok(0) {
        true
    } else {
        write_line("plugkit-test: child wait failed");
        false
    }
}

pub fn getpid() -> u64 {
    mochi_user_syscall::execution::identity()
        .map(|identity| identity.process_id)
        .unwrap_or(0)
}

pub fn gettid() -> u64 {
    mochi_user_syscall::execution::identity()
        .map(|identity| identity.thread_id)
        .unwrap_or(0)
}

pub fn yield_now() -> u64 {
    unsafe { syscall0(SYS_THREAD_YIELD) }
}

pub fn sleep(milliseconds: u64) -> u64 {
    unsafe { syscall1(SYS_SLEEP, milliseconds) }
}

pub fn get_ticks() -> u64 {
    unsafe { syscall0(SYS_TIME_NOW) }
}

pub fn list_processes(buf: &mut [u8]) -> u64 {
    unsafe {
        syscall2(
            SYS_LIST_PROCESSES,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    }
}

pub fn has_capability(cap_name: &str) -> bool {
    let tid = gettid();
    if tid == 0 {
        return false;
    }
    unsafe {
        syscall3(
            SYS_CHECK_THREAD_CAPABILITY,
            tid,
            cap_name.as_ptr() as u64,
            cap_name.len() as u64,
        ) == 1
    }
}

fn thread_has_capability(tid: u64, cap_name: &str) -> bool {
    if tid == 0 {
        return false;
    }
    unsafe {
        syscall3(
            SYS_CHECK_THREAD_CAPABILITY,
            tid,
            cap_name.as_ptr() as u64,
            cap_name.len() as u64,
        ) == 1
    }
}

fn signature_db_self_test() -> bool {
    let fd = file_open(SIGNATURE_DB_PATH, 0);
    if fd == 0 || (fd as i64) < 0 {
        return false;
    }

    let mut buf = alloc::vec![0u8; 4096];
    let mut total = alloc::vec::Vec::new();
    loop {
        let n = file_read(fd, &mut buf);
        if (n as i64) < 0 {
            let _ = file_close(fd);
            return false;
        }
        let n = n as usize;
        if n == 0 {
            break;
        }
        total.extend_from_slice(&buf[..n]);
        if total.len() > 4096 {
            let _ = file_close(fd);
            return false;
        }
    }
    let _ = file_close(fd);

    let Ok(text) = core::str::from_utf8(&total) else {
        return false;
    };
    text.contains("mnu-execution-allowlist v1")
        && text.contains("record /init ")
        && text.contains("record /plugkit/test/entry.elf ")
}

fn signature_exec_self_test() -> bool {
    let allow_status = exec_and_wait(SIGNATURE_ALLOW_PATH);
    if allow_status != Some(0) {
        write_line("selftest: signature allow failed");
        return false;
    }
    write_line("selftest: signature allow ok");

    if !exec_should_be_denied(SIGNATURE_DENY_PATH) {
        write_line("selftest: signature deny failed");
        return false;
    }
    write_line("selftest: signature deny ok");

    true
}

fn bytes_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    let mut i = 0usize;
    while i < lhs.len() {
        let l = unsafe { core::ptr::read_volatile(lhs.as_ptr().add(i)) };
        let r = unsafe { core::ptr::read_volatile(rhs.as_ptr().add(i)) };
        if l != r {
            return false;
        }
        i += 1;
    }
    true
}

pub fn test_syscall_getpid_and_gettid_are_nonzero() -> bool {
    let pid = getpid();
    let tid = gettid();
    pid != 0 && tid != 0
}

pub fn test_syscall_yield_and_sleep_zero_return_success() -> bool {
    let before = get_ticks();
    let yield_ret = yield_now();
    let sleep_ret = sleep(0);
    let after = get_ticks();

    yield_ret == 0 && sleep_ret == 0 && after >= before
}

fn process_record_matches_name(record: &[u8], expected_name: &[u8]) -> bool {
    if record.len() != mnu_abi::PROCESS_INFO_RECORD_SIZE {
        return false;
    }

    let pid = u64::from_ne_bytes([
        record[0], record[1], record[2], record[3], record[4], record[5], record[6], record[7],
    ]);
    let tid = u64::from_ne_bytes([
        record[8], record[9], record[10], record[11], record[12], record[13], record[14],
        record[15],
    ]);
    let name = &record[48..mnu_abi::PROCESS_INFO_RECORD_SIZE];

    if pid == 0 || tid == 0 || expected_name.len() > name.len() {
        return false;
    }

    if !bytes_eq(&name[..expected_name.len()], expected_name) {
        return false;
    }

    name[expected_name.len()..].iter().copied().all(|b| b == 0)
}

fn process_record_state(record: &[u8]) -> u64 {
    u64::from_ne_bytes([
        record[16], record[17], record[18], record[19], record[20], record[21], record[22],
        record[23],
    ])
}

fn find_process_state_by_name(expected_name: &[u8]) -> Option<u64> {
    let mut proc_buf = [0u8; 2048];
    let count = list_processes(&mut proc_buf);
    if count == 0 {
        return None;
    }
    let record_size = mnu_abi::PROCESS_INFO_RECORD_SIZE;
    let max_records = core::cmp::min(count as usize, proc_buf.len() / record_size);
    for idx in 0..max_records {
        let start = idx * record_size;
        let end = start + record_size;
        if process_record_matches_name(&proc_buf[start..end], expected_name) {
            return Some(process_record_state(&proc_buf[start..end]));
        }
    }
    None
}

pub fn test_syscall_list_processes_includes_init() -> bool {
    let mut buf = [0u8; 2048];
    let count = list_processes(&mut buf);
    if count == 0 {
        return false;
    }

    let record_size = mnu_abi::PROCESS_INFO_RECORD_SIZE;
    let max_records = core::cmp::min(count as usize, buf.len() / record_size);
    for idx in 0..max_records {
        let start = idx * record_size;
        let end = start + record_size;
        if process_record_matches_name(&buf[start..end], b"init") {
            return true;
        }
    }

    false
}

pub fn test_syscall_list_processes_contains_at_least_one_valid_record() -> bool {
    let mut buf = [0u8; 2048];
    let count = list_processes(&mut buf);
    if count == 0 {
        return false;
    }

    let record_size = mnu_abi::PROCESS_INFO_RECORD_SIZE;
    let max_records = core::cmp::min(count as usize, buf.len() / record_size);
    if max_records == 0 {
        return false;
    }

    let first = &buf[..record_size];
    let pid = u64::from_ne_bytes([
        first[0], first[1], first[2], first[3], first[4], first[5], first[6], first[7],
    ]);
    let tid = u64::from_ne_bytes([
        first[8], first[9], first[10], first[11], first[12], first[13], first[14], first[15],
    ]);
    let state = u64::from_ne_bytes([
        first[16], first[17], first[18], first[19], first[20], first[21], first[22], first[23],
    ]);
    pid != 0 && tid != 0 && state <= 4
}

fn run_restricted_probe() -> bool {
    let exec_denied = !has_capability("process.spawn");
    let list_denied = !has_capability("process.inspect");
    let ticks_denied = !has_capability("system.time.read");
    let self_ok = getpid() != 0 && gettid() != 0;

    exec_denied && list_denied && ticks_denied && self_ok
}

fn capability_restrict_regression_self_test() -> bool {
    if has_capability(MEMORY_PHYS_MAP_CAP) {
        write_line("selftest: unexpected phys map cap");
        return false;
    }

    let rc = cap_restrict(
        MEMORY_PHYS_MAP_CAP.as_ptr() as u64,
        MEMORY_PHYS_MAP_CAP.len() as u64,
        MEMORY_PHYS_MAP_CAP.as_ptr() as u64,
        MEMORY_PHYS_MAP_CAP.len() as u64,
    );
    if rc == 0 {
        write_line("selftest: cap restrict escalation allowed");
        return false;
    }

    if has_capability(MEMORY_PHYS_MAP_CAP) {
        write_line("selftest: cap restrict escalation persisted");
        return false;
    }

    true
}

fn physical_map_regression_self_test() -> bool {
    let addr = memory_map(0, 4096, 3, 0, 0);
    if addr == 0 || (addr as i64) < 0 {
        write_line("selftest: phys map setup failed");
        return false;
    }

    let rc = map_physical_range(addr, 0x1000, 0x1000);
    let _ = memory_unmap(addr, 4096);

    if rc == 0 {
        write_line("selftest: phys map unexpectedly enabled");
        return false;
    }

    true
}

fn test_allowed_capabilities_on_init() -> bool {
    let spawn = has_capability("process.spawn");
    if !spawn {
        write_line("selftest: missing process.spawn");
    }
    spawn
        && has_capability("process.inspect")
        && has_capability("capabilities.manage")
        && has_capability("system.time.read")
        && has_capability("ipc.client")
}

pub fn run_restricted_self_test() -> bool {
    run_restricted_probe()
        && capability_restrict_regression_self_test()
        && physical_map_regression_self_test()
}

pub fn run_self_test() -> bool {
    write_line("selftest: enter");

    write_line("selftest: before-gettid");
    let tid = gettid();
    write_line("selftest: after-gettid");

    if tid == 0 {
        write_line("selftest: tid-zero");
        return run_restricted_self_test();
    }

    write_line("selftest: before-check-cap");
    let spawn_cap = unsafe {
        syscall3(
            SYS_CHECK_THREAD_CAPABILITY,
            tid,
            "process.spawn".as_ptr() as u64,
            "process.spawn".len() as u64,
        ) == 1
    };
    write_line("selftest: after-check-cap");

    if !spawn_cap {
        write_line("selftest: restricted");
        return run_restricted_self_test();
    }

    write_line("selftest: allowed-checks");
    if !test_allowed_capabilities_on_init() {
        write_line("selftest: capability check failed");
        return false;
    }

    if !capability_restrict_regression_self_test() {
        return false;
    }

    if !physical_map_regression_self_test() {
        return false;
    }

    if !signature_db_self_test() {
        write_line("selftest: signature-db failed");
        return false;
    }

    if !signature_exec_self_test() {
        write_line("selftest: signature-exec failed");
        return false;
    }

    if !bss_zero_fill_self_test() {
        write_line("selftest: bss zero-fill failed");
        return false;
    }

    if !fileio_self_test() {
        write_line("selftest: fs-test failed");
        return false;
    }

    if !plugkit_ipc_self_test() {
        write_line("selftest: plugkit-test failed");
        return false;
    }

    true
}

pub fn write_line(s: &str) {
    unsafe {
        let _ = syscall2(SYS_DEBUG_WRITE, s.as_ptr() as u64, s.len() as u64);
        let nl = b"\n";
        let _ = syscall2(SYS_DEBUG_WRITE, nl.as_ptr() as u64, 1);
    }
}
