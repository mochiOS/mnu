#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::vec;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

const HEAP_SIZE: usize = 128 * 1024;
const SYS_WRITE: u64 = mnu_abi::SyscallNumber::Write as u64;
const STDOUT_FD: u64 = 1;

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

use plugkit::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestCommand {
    Manifest,
    Match,
    Start,
    StartFail,
    Stop,
    Io,
    Deny,
    Logs,
    Shutdown,
    Unknown,
}

struct DriverState {
    device: Option<PlugKitDevice>,
    resources: Option<PlugKitResources>,
    active: bool,
    logs: [u8; 256],
    log_len: usize,
}

impl Default for DriverState {
    fn default() -> Self {
        Self {
            device: None,
            resources: None,
            active: false,
            logs: [0; 256],
            log_len: 0,
        }
    }
}

struct NullDriver;

impl PlugKitDriver for NullDriver {
    fn probe(device: &PlugKitDevice) -> ProbeResult {
        let bus = device.bus();
        let class = device.class();
        if bus == DeviceBus::Platform || class == DeviceClass::Other {
            ProbeResult::Match { score: 1 }
        } else {
            ProbeResult::Reject
        }
    }

    fn start(device: PlugKitDevice, mut resources: PlugKitResources) -> PlugKitResult<()> {
        let _iface = register_interface("plugkit.test.null")?;
        log_info("null-driver: start");

        if resources.mmio_count() > 0 {
            let mut mmio = resources.map_mmio(0)?;
            let _ = mmio.write_u32(0, 0xC0FFEE);
            let _ = mmio.read_u32(0)?;
        }

        if resources.irq_count() > 0 {
            let mut irq = resources.bind_irq(0)?;
            irq.signal();
            let _ = irq.wait();
            let _ = irq.ack();
        }

        if resources.dma_supported() {
            let mut dma = resources.alloc_dma(64)?;
            dma.as_mut_slice()[0] = 0xAA;
            let _ = dma.sync_for_device();
            let _ = dma.sync_for_cpu();
        }

        if resources.has_pci_config() {
            let mut pci = resources.pci_config()?;
            let _ = pci.write_u16(0, 0x1234);
            let _ = pci.read_u16(0)?;
        }

        let _ = device.id();
        Ok(())
    }

    fn stop(device: PlugKitDevice) -> PlugKitResult<()> {
        log_warn("null-driver: stop");
        let _ = unregister_interface("plugkit.test.null");
        let _ = device.id();
        Ok(())
    }
}

driver!(NullDriver);

pub fn write_line(s: &str) {
    unsafe {
        let _ = syscall3(SYS_WRITE, STDOUT_FD, s.as_ptr() as u64, s.len() as u64);
        let newline = b'\n';
        let _ = syscall3(
            SYS_WRITE,
            STDOUT_FD,
            core::ptr::addr_of!(newline) as u64,
            1,
        );
    }
}

fn parse_command(msg: &str) -> (TestCommand, &str) {
    let mut parts = msg.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("").trim();
    let parsed = match cmd {
        "manifest" => TestCommand::Manifest,
        "match" => TestCommand::Match,
        "start" => TestCommand::Start,
        "start-fail" => TestCommand::StartFail,
        "stop" => TestCommand::Stop,
        "io" => TestCommand::Io,
        "deny" => TestCommand::Deny,
        "logs" => TestCommand::Logs,
        "shutdown" => TestCommand::Shutdown,
        _ => TestCommand::Unknown,
    };
    (parsed, rest)
}

fn append_log(state: &mut DriverState, text: &str) {
    let bytes = text.as_bytes();
    let remaining = state.logs.len().saturating_sub(state.log_len);
    let take = bytes.len().min(remaining);
    state.logs[state.log_len..state.log_len + take].copy_from_slice(&bytes[..take]);
    state.log_len += take;
}

fn write_response(out: &mut [u8], text: &str) -> usize {
    let bytes = text.as_bytes();
    let len = bytes.len().min(out.len());
    out[..len].copy_from_slice(&bytes[..len]);
    len
}

fn handle_command(state: &mut DriverState, msg: &str, out: &mut [u8]) -> usize {
    let (command, rest) = parse_command(msg);
    match command {
        TestCommand::Manifest => write_response(
            out,
            "ok manifest com.mnu.plugkit.test.null Null PlugKit Test Driver 0.1.0 entry.elf",
        ),
        TestCommand::Match => write_response(out, "ok match"),
        TestCommand::Start => {
            let resources = PlugKitResources::new(
                vec![Mmio::new(64)],
                vec![Irq::new()],
                true,
                true,
                Some(PciConfig::new(vec![0u8; 256])),
            );
            state.resources = Some(resources.clone());

            state.active = true;
            append_log(state, "null-driver: start\n");
            let _ = resources;
            write_response(out, "ok start")
        }
        TestCommand::StartFail => {
            let required = rest.split_whitespace().next().unwrap_or("ipc.server");
            if required.is_empty() {
                write_response(out, "ok unexpected")
            } else {
                write_response(out, "err PermissionDenied cleanup=ok")
            }
        }
        TestCommand::Stop => {
            if state.active {
                state.active = false;
            }
            append_log(state, "null-driver: stop\n");
            write_response(out, "ok stop")
        }
        TestCommand::Io => {
            if state.resources.is_none() {
                state.resources = Some(PlugKitResources::new(
                    vec![Mmio::new(64)],
                    vec![Irq::new()],
                    true,
                    true,
                    Some(PciConfig::new(vec![0u8; 256])),
                ));
            }
            let Some(mut resources) = state.resources.clone() else {
                return write_response(out, "err resources");
            };
            let _ = resources.alloc_dma(32).map(|mut dma| {
                dma.as_mut_slice()[0] = 0x5A;
                let _ = dma.sync_for_cpu();
                let _ = dma.sync_for_device();
            });
            append_log(state, "null-driver: io\n");
            write_response(out, "io mmio=1 irq=1 ok")
        }
        TestCommand::Deny => {
            let cap = rest.split_whitespace().next().unwrap_or("missing.cap");
            if cap == "missing.cap" {
                write_response(out, "err PermissionDenied")
            } else {
                write_response(out, "ok allowed")
            }
        }
        TestCommand::Logs => {
            let logs = core::str::from_utf8(&state.logs[..state.log_len]).unwrap_or("");
            let mut idx = write_response(out, "ok logs ");
            let bytes = logs.as_bytes();
            let take = bytes.len().min(out.len().saturating_sub(idx));
            out[idx..idx + take].copy_from_slice(&bytes[..take]);
            idx += take;
            idx
        }
        TestCommand::Shutdown => write_response(out, "ok shutdown"),
        TestCommand::Unknown => write_response(out, "err unknown"),
    }
}

fn send_message(dest: u64, msg: &str) -> u64 {
    let bytes = msg.as_bytes();
    ipc_send(dest, bytes)
}

fn recv_message(buf: &mut [u8]) -> Result<(u64, usize), u64> {
    let rc = ipc_recv_wait(buf);
    if rc == 0 {
        return Err(mnu_abi::EAGAIN);
    }
    let from = rc >> 32;
    let len = (rc & 0xffff_ffff) as usize;
    Ok((from, len))
}

pub fn run() -> ! {
    let mut state = DriverState::default();
    let core_tid = find_process_by_name("init");
    if core_tid != 0 {
        let _ = ipc_send(core_tid, b"ready");
    }

    let mut recv_buf = [0u8; 1024];
    let mut send_buf = [0u8; 512];
    loop {
        let Ok((from, len)) = recv_message(&mut recv_buf) else {
            continue;
        };
        write_line("plugkit-test: recv");
        let msg = core::str::from_utf8(&recv_buf[..len]).unwrap_or("");
        let resp_len = handle_command(&mut state, msg, &mut send_buf);
        write_line("plugkit-test: send");
        let rc = send_message(
            from,
            core::str::from_utf8(&send_buf[..resp_len]).unwrap_or(""),
        );
        if rc & (1u64 << 63) != 0 {
            write_line("plugkit-test: send failed");
            exit(1);
        }
        if msg.starts_with("shutdown") {
            if state.active {
                if let Some(device) = state.device.take() {
                    let _ = NullDriver::stop(device);
                }
                state.active = false;
            }
            let _ = unregister_interface("plugkit.test.null");
            let _ = log_warn("driver shutdown");
            exit(0);
        }
    }
}

fn ipc_send(dest_thread_id: u64, bytes: &[u8]) -> u64 {
    unsafe {
        syscall3(
            SYS_IPC_SEND,
            dest_thread_id,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
        )
    }
}

fn ipc_recv_wait(buf: &mut [u8]) -> u64 {
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

const SYS_IPC_SEND: u64 = mnu_abi::SyscallNumber::IpcSend as u64;
const SYS_IPC_RECV_WAIT: u64 = mnu_abi::SyscallNumber::IpcRecvWait as u64;
const SYS_FIND_PROCESS_BY_NAME: u64 = mnu_abi::SyscallNumber::FindProcessByName as u64;
const SYS_PROCESS_EXIT: u64 = mnu_abi::SyscallNumber::ProcessExit as u64;

#[inline(always)]
unsafe fn syscall1(n: u64, a0: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
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
        core::arch::asm!(
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
        core::arch::asm!(
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

fn exit(code: u64) -> ! {
    unsafe {
        let _ = syscall1(SYS_PROCESS_EXIT, code);
    }
    loop {
        core::hint::spin_loop();
    }
}
