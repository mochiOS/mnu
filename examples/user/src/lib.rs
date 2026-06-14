#![no_std]

use core::arch::asm;

/// kernel 側 policy に渡す launch contract の userland 側表現
///
/// ここでは manifest のパースは扱わず、固定のデータ形だけを検証する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestRole {
    CoreService,
    Service,
    Application,
    Driver,
    Tool,
    Unknown,
}

/// install source の userland 側表現
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallSource {
    Initfs,
    Rootfs,
    BuiltIn,
    PackageStore,
    RemovableMedia,
    Network,
    Debug,
    Unknown,
}

/// kernel の `LaunchSpec` に対応する最小 contract
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchContract {
    pub package_id: &'static str,
    pub publisher_id: &'static str,
    pub signature_trusted: bool,
    pub manifest_role: ManifestRole,
    pub file_digest: [u8; 32],
    pub install_source: InstallSource,
}

impl LaunchContract {
    pub fn new(
        package_id: &'static str,
        publisher_id: &'static str,
        signature_trusted: bool,
        manifest_role: ManifestRole,
        file_digest: [u8; 32],
        install_source: InstallSource,
    ) -> Self {
        Self {
            package_id,
            publisher_id,
            signature_trusted,
            manifest_role,
            file_digest,
            install_source,
        }
    }

    /// 形式上の最小要件だけを見る
    pub fn is_well_formed(&self) -> bool {
        !self.package_id.is_empty() && !self.publisher_id.is_empty()
    }
}

const SYS_WRITE: u64 = mnu_abi::SyscallNumber::Write as u64;
const SYS_EXIT: u64 = mnu_abi::SyscallNumber::Exit as u64;
const SYS_GETPID: u64 = mnu_abi::SyscallNumber::GetPid as u64;
const SYS_GETTID: u64 = mnu_abi::SyscallNumber::GetTid as u64;
const SYS_EXEC: u64 = mnu_abi::SyscallNumber::Exec as u64;
const SYS_EXEC_WITH_CAPS: u64 = mnu_abi::SyscallNumber::ExecWithCapabilities as u64;
const SYS_IPC_SEND: u64 = mnu_abi::SyscallNumber::IpcSend as u64;
const SYS_IPC_RECV_WAIT: u64 = mnu_abi::SyscallNumber::IpcRecvWait as u64;
const SYS_WAIT: u64 = mnu_abi::SyscallNumber::Wait as u64;
const SYS_YIELD: u64 = mnu_abi::SyscallNumber::Yield as u64;
const SYS_SLEEP: u64 = mnu_abi::SyscallNumber::Sleep as u64;
const SYS_GET_TICKS: u64 = mnu_abi::SyscallNumber::GetTicks as u64;
const SYS_CHECK_THREAD_CAPABILITY: u64 = mnu_abi::SyscallNumber::CheckThreadCapability as u64;
const SYS_LIST_PROCESSES: u64 = mnu_abi::SyscallNumber::ListProcesses as u64;
const SYS_FIND_PROCESS_BY_NAME: u64 = mnu_abi::SyscallNumber::FindProcessByName as u64;
const SYS_FILE_OPEN: u64 = mnu_abi::SyscallNumber::FileOpen as u64;
#[allow(dead_code)]
const SYS_FILE_OPEN_AT: u64 = mnu_abi::SyscallNumber::FileOpenAt as u64;
const SYS_FILE_CLOSE: u64 = mnu_abi::SyscallNumber::FileClose as u64;
const SYS_FILE_READ: u64 = mnu_abi::SyscallNumber::FileRead as u64;
const SYS_FILE_WRITE: u64 = mnu_abi::SyscallNumber::FileWrite as u64;
const SYS_FILE_SEEK: u64 = mnu_abi::SyscallNumber::FileSeek as u64;
const STDOUT_FD: u64 = 1;
const PLUGKIT_TEST_DRIVER_PATH: &str = "/plugkit/test/entry.elf";
const FS_TEST_SIZE: usize = 1024 * 1024;
static mut FS_TEST_WRITE_BUF: [u8; FS_TEST_SIZE] = [0x55; FS_TEST_SIZE];
static mut FS_TEST_READ_BUF: [u8; FS_TEST_SIZE] = [0; FS_TEST_SIZE];

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
        let _ = syscall3(SYS_WRITE, STDOUT_FD, s.as_ptr() as u64, s.len() as u64);
    }
}

fn file_path_bytes(path: &str) -> [u8; 96] {
    let mut buf = [0u8; 96];
    let bytes = path.as_bytes();
    let len = bytes.len().min(buf.len() - 1);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf[len] = 0;
    buf
}

fn file_open(path: &str, flags: u64) -> u64 {
    let buf = file_path_bytes(path);
    unsafe { syscall2(SYS_FILE_OPEN, buf.as_ptr() as u64, flags) }
}

#[allow(dead_code)]
fn file_open_at(dirfd: i64, path: &str, flags: u64, mode: u64) -> u64 {
    let buf = file_path_bytes(path);
    unsafe { syscall4(SYS_FILE_OPEN_AT, dirfd as u64, buf.as_ptr() as u64, flags, mode) }
}

fn file_close(fd: u64) -> u64 {
    unsafe { syscall1(SYS_FILE_CLOSE, fd) }
}

fn file_read(fd: u64, buf: &mut [u8]) -> u64 {
    unsafe { syscall3(SYS_FILE_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

fn file_write(fd: u64, buf: &[u8]) -> u64 {
    unsafe { syscall3(SYS_FILE_WRITE, fd, buf.as_ptr() as u64, buf.len() as u64) }
}

fn file_seek(fd: u64, offset: i64, whence: u64) -> u64 {
    unsafe { syscall3(SYS_FILE_SEEK, fd, offset as u64, whence) }
}

fn exec_with_capabilities(path: &str, caps: &[&str]) -> u64 {
    let mut path_buf = [0u8; 128];
    let path_bytes = path.as_bytes();
    if path_bytes.len() + 1 > path_buf.len() {
        return mnu_abi::EINVAL as u64;
    }
    path_buf[..path_bytes.len()].copy_from_slice(path_bytes);
    path_buf[path_bytes.len()] = 0;

    let mut caps_buf = [0u8; 256];
    let mut len = 0usize;
    for cap in caps {
        let bytes = cap.as_bytes();
        if len + bytes.len() + 1 >= caps_buf.len() {
            return mnu_abi::EINVAL as u64;
        }
        caps_buf[len..len + bytes.len()].copy_from_slice(bytes);
        len += bytes.len();
        caps_buf[len] = 0;
        len += 1;
    }

    unsafe {
        syscall4(
            SYS_EXEC_WITH_CAPS,
            path_buf.as_ptr() as u64,
            0,
            caps_buf.as_ptr() as u64,
            len as u64,
        )
    }
}

fn ipc_send(dest: u64, buf: &[u8]) -> u64 {
    unsafe { syscall3(SYS_IPC_SEND, dest, buf.as_ptr() as u64, buf.len() as u64) }
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
    unsafe { syscall2(SYS_FIND_PROCESS_BY_NAME, name_buf.as_ptr() as u64, bytes.len() as u64) }
}

fn launch_plugkit_test_driver() -> Option<u64> {
    let pid = exec_with_capabilities(
        PLUGKIT_TEST_DRIVER_PATH,
        &["ipc.client", "ipc.server", "fs.read.all", "fs.write.all"],
    );
    if pid & (1u64 << 63) != 0 || pid == 0 {
        None
    } else {
        for _ in 0..100 {
            let tid = find_process_by_name("com.mnu.plugkit.test.null");
            if tid != 0 {
                return Some(tid);
            }
            let tid = find_process_by_name(PLUGKIT_TEST_DRIVER_PATH);
            if tid != 0 {
                return Some(tid);
            }
            let _ = yield_now();
        }
        None
    }
}

fn recv_ipc_response(buf: &mut [u8]) -> Option<(u64, usize)> {
    let rc = ipc_recv_wait(buf);
    if rc == 0 || rc & (1u64 << 63) != 0 {
        return None;
    }
    Some((rc >> 32, (rc & 0xffff_ffff) as usize))
}

fn ipc_round_trip(dest: u64, msg: &str, buf: &mut [u8]) -> Option<usize> {
    let sent = ipc_send(dest, msg.as_bytes());
    if sent & (1u64 << 63) != 0 {
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
        format_args!("{} {} bytes in {} ms: {:.1} MiB/s", prefix, bytes, elapsed_ms, mib_s),
    );
    line
}

fn fileio_self_test() -> bool {
    const TICK_MS: u64 = 2;

    let path = "/core.service.fs-test";
    let payload = unsafe {
        core::slice::from_raw_parts(core::ptr::addr_of!(FS_TEST_WRITE_BUF) as *const u8, FS_TEST_SIZE)
    };
    let buffer = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(FS_TEST_READ_BUF) as *mut u8,
            FS_TEST_SIZE,
        )
    };

    let fd = file_open(path, 0o2 | 0o100 | 0o1000);
    if fd == mnu_abi::EBADF as u64 || fd == mnu_abi::ENOENT as u64 {
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
    let ro_write_errno = if ro_fd < (1u64 << 63) {
        let rc = file_write(ro_fd, &payload[..16]);
        let _ = file_close(ro_fd);
        rc
    } else {
        ro_fd
    };

    let wo_fd = file_open(path, 0o1 | 0o100);
    let wo_read_errno = if wo_fd < (1u64 << 63) {
        let rc = file_read(wo_fd, &mut buffer[..16]);
        let _ = file_close(wo_fd);
        rc
    } else {
        wo_fd
    };

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

    let write_line_buf = format_line("[core.service][fs-test] write", wrote, write_elapsed_ms, write_mib_s);
    let read_line_buf = format_line("[core.service][fs-test] read ", read, read_elapsed_ms, read_mib_s);
    write_line(write_line_buf.as_str());
    write_line(read_line_buf.as_str());

    same
        && closed_errno == mnu_abi::EBADF as u64
        && ro_write_errno == mnu_abi::EACCES as u64
        && wo_read_errno == mnu_abi::EACCES as u64
}

fn plugkit_ipc_self_test() -> bool {
    let Some(driver_tid) = launch_plugkit_test_driver() else {
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
        let record_size = 88usize;
        let max_records = core::cmp::min(count as usize, proc_buf.len() / record_size);
        for idx in 0..max_records {
            let start = idx * record_size;
            let end = start + record_size;
            if process_record_matches_name(
                &proc_buf[start..end],
                b"com.mnu.plugkit.test.null",
            ) {
                let state = process_record_state(&proc_buf[start..end]);
                let mut line = LineBuf::new();
                let _ = core::fmt::write(
                    &mut line,
                    format_args!("plugkit-test state {}", state),
                );
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

    match wait_for_any_child() {
        Ok((_pid, status)) if status == 0 => true,
        _ => {
            write_line("plugkit-test: child wait failed");
            false
        }
    }
}

pub fn exit(code: u64) -> ! {
    unsafe {
        let _ = syscall1(SYS_EXIT, code);
    }
    loop {
        unsafe {
            asm!("pause", options(nomem, nostack, preserves_flags));
        }
    }
}

pub fn getpid() -> u64 {
    unsafe { syscall0(SYS_GETPID) }
}

pub fn gettid() -> u64 {
    unsafe { syscall0(SYS_GETTID) }
}

pub fn yield_now() -> u64 {
    unsafe { syscall0(SYS_YIELD) }
}

pub fn sleep(milliseconds: u64) -> u64 {
    unsafe { syscall1(SYS_SLEEP, milliseconds) }
}

pub fn get_ticks() -> u64 {
    unsafe { syscall0(SYS_GET_TICKS) }
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

pub fn exec_without_caps(path: &str) -> u64 {
    let mut path_buf = [0u8; 128];
    let path_bytes = path.as_bytes();
    if path_bytes.len() + 1 > path_buf.len() {
        return mnu_abi::EINVAL as u64;
    }
    path_buf[..path_bytes.len()].copy_from_slice(path_bytes);
    path_buf[path_bytes.len()] = 0;

    unsafe { syscall2(SYS_EXEC, path_buf.as_ptr() as u64, 0) }
}

pub fn wait_for_any_child() -> Result<(u64, i32), u64> {
    let mut status: i32 = -1;
    let waited = unsafe { syscall3(SYS_WAIT, u64::MAX, &mut status as *mut i32 as u64, 0) };
    if waited & (1u64 << 63) == 0 {
        Ok((waited, status))
    } else {
        Err(waited)
    }
}

pub fn test_launch_contract_keeps_all_required_fields() -> bool {
    let digest = [0xAB; 32];
    let contract = LaunchContract::new(
        "core.service",
        "mnu",
        true,
        ManifestRole::CoreService,
        digest,
        InstallSource::Initfs,
    );

    contract.package_id == "core.service"
        && contract.publisher_id == "mnu"
        && contract.signature_trusted
        && contract.manifest_role == ManifestRole::CoreService
        && contract.file_digest == digest
        && contract.install_source == InstallSource::Initfs
        && contract.is_well_formed()
}

pub fn test_launch_contract_rejects_empty_identity_fields() -> bool {
    let contract = LaunchContract::new(
        "",
        "",
        false,
        ManifestRole::Unknown,
        [0; 32],
        InstallSource::Unknown,
    );

    !contract.is_well_formed()
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
    if record.len() != 88 {
        return false;
    }

    let pid = u64::from_ne_bytes([
        record[0], record[1], record[2], record[3], record[4], record[5], record[6], record[7],
    ]);
    let tid = u64::from_ne_bytes([
        record[8], record[9], record[10], record[11], record[12], record[13], record[14],
        record[15],
    ]);
    let name = &record[32..88];

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
    let record_size = 88usize;
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

pub fn test_syscall_list_processes_includes_core_service() -> bool {
    let mut buf = [0u8; 2048];
    let count = list_processes(&mut buf);
    if count == 0 {
        return false;
    }

    let record_size = 88usize;
    let max_records = core::cmp::min(count as usize, buf.len() / record_size);
    for idx in 0..max_records {
        let start = idx * record_size;
        let end = start + record_size;
        if process_record_matches_name(&buf[start..end], b"core.service") {
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

    let record_size = 88usize;
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
    let exec_denied = unsafe { syscall2(SYS_EXEC, 0, 0) } == mnu_abi::EPERM as u64;
    let mut buf = [0u8; 256];
    let list_denied = list_processes(&mut buf) == mnu_abi::EPERM as u64;
    let ticks_denied = get_ticks() == mnu_abi::EPERM as u64;
    let self_ok = getpid() != 0 && gettid() != 0;

    exec_denied && list_denied && ticks_denied && self_ok
}

fn test_allowed_capabilities_on_core_service() -> bool {
    has_capability("process.spawn")
        && has_capability("process.inspect")
        && has_capability("system.time.read")
        && has_capability("ipc.client")
}

pub fn run_restricted_self_test() -> bool {
    run_restricted_probe()
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
    if !test_allowed_capabilities_on_core_service() {
        write_line("selftest: capability check failed");
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
        let _ = syscall3(SYS_WRITE, STDOUT_FD, s.as_ptr() as u64, s.len() as u64);
        let nl = b"\n";
        let _ = syscall3(SYS_WRITE, STDOUT_FD, nl.as_ptr() as u64, 1);
    }
}
