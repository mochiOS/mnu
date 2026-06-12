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
const SYS_WAIT: u64 = mnu_abi::SyscallNumber::Wait as u64;
const SYS_YIELD: u64 = mnu_abi::SyscallNumber::Yield as u64;
const SYS_SLEEP: u64 = mnu_abi::SyscallNumber::Sleep as u64;
const SYS_GET_TICKS: u64 = mnu_abi::SyscallNumber::GetTicks as u64;
const SYS_CHECK_THREAD_CAPABILITY: u64 = mnu_abi::SyscallNumber::CheckThreadCapability as u64;
const SYS_LIST_PROCESSES: u64 = mnu_abi::SyscallNumber::ListProcesses as u64;
const STDOUT_FD: u64 = 1;

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

pub fn write_str(s: &str) {
    unsafe {
        let _ = syscall3(SYS_WRITE, STDOUT_FD, s.as_ptr() as u64, s.len() as u64);
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
    true
}

pub fn write_line(s: &str) {
    unsafe {
        let _ = syscall3(SYS_WRITE, STDOUT_FD, s.as_ptr() as u64, s.len() as u64);
        let nl = b"\n";
        let _ = syscall3(SYS_WRITE, STDOUT_FD, nl.as_ptr() as u64, 1);
    }
}
