#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = mnu_abi::SyscallNumber::Write as u64;
const SYS_EXIT: u64 = mnu_abi::SyscallNumber::Exit as u64;
const SYS_GETTID: u64 = mnu_abi::SyscallNumber::GetTid as u64;
const SYS_FIND_PROCESS_BY_NAME: u64 = mnu_abi::SyscallNumber::FindProcessByName as u64;
const SYS_LIST_PROCESSES: u64 = mnu_abi::SyscallNumber::ListProcesses as u64;
const SYS_GET_THREAD_PRIVILEGE: u64 = mnu_abi::SyscallNumber::GetThreadPrivilege as u64;
const STDOUT_FD: u64 = 1;

static mut PROCESS_BUF: [u8; 2048] = [0; 2048];

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_line("userland self-test: start");

    let contract_ok = test_contract();
    report_case("contract", contract_ok);

    let empty_ok = test_empty_contract();
    report_case("contract-empty", empty_ok);

    let privilege_ok = test_privilege();
    report_case("privilege", privilege_ok);

    let find_ok = test_find_process();
    report_case("find_process", find_ok);

    let list_ok = test_list_processes();
    report_case("list_processes", list_ok);

    let pass = contract_ok
        && empty_ok
        && privilege_ok
        && find_ok
        && list_ok;

    if pass {
        write_line("USERLAND SELF-TEST PASS");
        unsafe {
            let _ = syscall1(SYS_EXIT, 0);
        }
    } else {
        write_line("USERLAND SELF-TEST FAIL");
        unsafe {
            let _ = syscall1(SYS_EXIT, 1);
        }
    }

    loop {
        unsafe {
            asm!("pause", options(nomem, nostack, preserves_flags));
        }
    }
}

#[inline(never)]
fn test_contract() -> bool {
    let digest = [0xAB; 32];
    let contract = user::LaunchContract {
        package_id: "core.service",
        publisher_id: "mnu",
        signature_trusted: true,
        manifest_role: user::ManifestRole::CoreService,
        file_digest: digest,
        install_source: user::InstallSource::Initfs,
    };
    bytes_eq(contract.package_id.as_bytes(), b"core.service")
        && bytes_eq(contract.publisher_id.as_bytes(), b"mnu")
        && contract.signature_trusted
        && contract.manifest_role == user::ManifestRole::CoreService
        && bytes_eq(&contract.file_digest, &digest)
        && contract.install_source == user::InstallSource::Initfs
        && !contract.package_id.is_empty()
        && !contract.publisher_id.is_empty()
}

#[inline(never)]
fn test_empty_contract() -> bool {
    let contract = user::LaunchContract {
        package_id: "",
        publisher_id: "",
        signature_trusted: false,
        manifest_role: user::ManifestRole::Unknown,
        file_digest: [0; 32],
        install_source: user::InstallSource::Unknown,
    };
    contract.package_id.is_empty() && contract.publisher_id.is_empty()
}

#[inline(never)]
fn test_privilege() -> bool {
    let tid = unsafe { syscall0(SYS_GETTID) };
    let privilege = unsafe { syscall1(SYS_GET_THREAD_PRIVILEGE, tid) };
    tid != 0 && privilege <= 2
}

#[inline(never)]
fn test_find_process() -> bool {
    let tid = unsafe { syscall2(SYS_FIND_PROCESS_BY_NAME, b"core.service".as_ptr() as u64, 12) };
    tid != 0
}

#[inline(never)]
fn test_list_processes() -> bool {
    let buf_ptr = core::ptr::addr_of_mut!(PROCESS_BUF) as *mut u8;
    let buf_len = 2048usize;
    let count = unsafe { syscall2(SYS_LIST_PROCESSES, buf_ptr as u64, buf_len as u64) };
    if count == 0 {
        return false;
    }

    let buf = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, buf_len) };
    let record_size = 88usize;
    let max_records = core::cmp::min(count as usize, buf.len() / record_size);
    for idx in 0..max_records {
        let start = idx * record_size;
        let end = start + record_size;
        let record = &buf[start..end];
        let pid = u64::from_ne_bytes([
            record[0], record[1], record[2], record[3], record[4], record[5], record[6],
            record[7],
        ]);
        let tid = u64::from_ne_bytes([
            record[8], record[9], record[10], record[11], record[12], record[13], record[14],
            record[15],
        ]);
        let state = u64::from_ne_bytes([
            record[16], record[17], record[18], record[19], record[20], record[21], record[22],
            record[23],
        ]);
        let name = &record[32..88];
        let has_name = name.len() >= 12
            && bytes_eq(&name[..12], b"core.service")
            && name[12..].iter().all(|b| *b == 0);
        if pid != 0 && tid != 0 && state <= 4 && has_name {
            return true;
        }
    }

    false
}

#[inline(always)]
fn report_case(label: &str, ok: bool) {
    if ok {
        write_line_concat(label, "PASS");
    } else {
        write_line_concat(label, "FAIL");
    }
}

#[inline(always)]
fn write_line_concat(left: &str, right: &str) {
    let mut buf = [0u8; 96];
    let mut n = 0usize;
    for b in left.as_bytes() {
        if n >= buf.len() {
            break;
        }
        buf[n] = *b;
        n += 1;
    }
    if n + 2 < buf.len() {
        buf[n] = b':';
        n += 1;
        buf[n] = b' ';
        n += 1;
    }
    for b in right.as_bytes() {
        if n >= buf.len() {
            break;
        }
        buf[n] = *b;
        n += 1;
    }
    if n < buf.len() {
        buf[n] = b'\n';
        n += 1;
    }
    let _ = unsafe { syscall3(SYS_WRITE, STDOUT_FD, buf.as_ptr() as u64, n as u64) };
}

#[inline(always)]
fn write_line(label: &str) {
    let mut buf = [0u8; 96];
    let mut n = 0usize;
    for b in label.as_bytes() {
        if n >= buf.len() {
            break;
        }
        buf[n] = *b;
        n += 1;
    }
    if n < buf.len() {
        buf[n] = b'\n';
        n += 1;
    }
    let _ = unsafe { syscall3(SYS_WRITE, STDOUT_FD, buf.as_ptr() as u64, n as u64) };
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_line("USERLAND SELF-TEST PANIC");
    unsafe {
        let _ = syscall1(SYS_EXIT, 1);
    }
    loop {
        unsafe {
            asm!("pause", options(nomem, nostack, preserves_flags));
        }
    }
}
