#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = mnu_abi::SyscallNumber::Write as u64;
const SYS_EXIT: u64 = mnu_abi::SyscallNumber::Exit as u64;
const SYS_GETPID: u64 = mnu_abi::SyscallNumber::GetPid as u64;
const SYS_GETTID: u64 = mnu_abi::SyscallNumber::GetTid as u64;
const SYS_GET_THREAD_PRIVILEGE: u64 = mnu_abi::SyscallNumber::GetThreadPrivilege as u64;
const SYS_YIELD: u64 = mnu_abi::SyscallNumber::Yield as u64;
const SYS_SLEEP: u64 = mnu_abi::SyscallNumber::Sleep as u64;
const SYS_GET_TICKS: u64 = mnu_abi::SyscallNumber::GetTicks as u64;
const STDOUT_FD: u64 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut pass = true;

    unsafe {
        let msg = b"userland self-test: start\n";
        let _ = syscall3(SYS_WRITE, STDOUT_FD, msg.as_ptr() as u64, msg.len() as u64);
    }

    {
        unsafe {
            let msg = b"userland self-test: contract\n";
            let _ = syscall3(SYS_WRITE, STDOUT_FD, msg.as_ptr() as u64, msg.len() as u64);
        }
        let digest = [0xAB; 32];
        let contract = user::LaunchContract {
            package_id: "core.service",
            publisher_id: "mnu",
            signature_trusted: true,
            manifest_role: user::ManifestRole::CoreService,
            file_digest: digest,
            install_source: user::InstallSource::Initfs,
        };
        pass &= bytes_eq(contract.package_id.as_bytes(), b"core.service");
        pass &= bytes_eq(contract.publisher_id.as_bytes(), b"mnu");
        pass &= contract.signature_trusted;
        pass &= contract.manifest_role == user::ManifestRole::CoreService;
        pass &= bytes_eq(&contract.file_digest, &digest);
        pass &= contract.install_source == user::InstallSource::Initfs;
        pass &= !contract.package_id.is_empty() && !contract.publisher_id.is_empty();
    }

    {
        unsafe {
            let msg = b"userland self-test: identity\n";
            let _ = syscall3(SYS_WRITE, STDOUT_FD, msg.as_ptr() as u64, msg.len() as u64);
        }
        let contract = user::LaunchContract {
            package_id: "",
            publisher_id: "",
            signature_trusted: false,
            manifest_role: user::ManifestRole::Unknown,
            file_digest: [0; 32],
            install_source: user::InstallSource::Unknown,
        };
        pass &= contract.package_id.is_empty() && contract.publisher_id.is_empty();
    }

    {
        unsafe {
            let msg = b"userland self-test: identity/syscalls\n";
            let _ = syscall3(SYS_WRITE, STDOUT_FD, msg.as_ptr() as u64, msg.len() as u64);
        }
        let pid = unsafe { syscall0(SYS_GETPID) };
        let tid = unsafe { syscall0(SYS_GETTID) };
        pass &= pid != 0 && tid != 0;
    }

    {
        unsafe {
            let msg = b"userland self-test: scheduler\n";
            let _ = syscall3(SYS_WRITE, STDOUT_FD, msg.as_ptr() as u64, msg.len() as u64);
        }
        let before = unsafe { syscall0(SYS_GET_TICKS) };
        let yield_ret = unsafe { syscall0(SYS_YIELD) };
        let sleep_ret = unsafe { syscall1(SYS_SLEEP, 0) };
        let after = unsafe { syscall0(SYS_GET_TICKS) };
        pass &= yield_ret == 0 && sleep_ret == 0 && after >= before;
    }

    {
        unsafe {
            let msg = b"userland self-test: privilege\n";
            let _ = syscall3(SYS_WRITE, STDOUT_FD, msg.as_ptr() as u64, msg.len() as u64);
        }
        let tid = unsafe { syscall0(SYS_GETTID) };
        let privilege = unsafe { syscall1(SYS_GET_THREAD_PRIVILEGE, tid) };
        pass &= tid != 0 && privilege <= 2;
    }

    if pass {
        unsafe {
            let msg = b"USERLAND SELF-TEST PASS\n";
            let _ = syscall3(SYS_WRITE, STDOUT_FD, msg.as_ptr() as u64, msg.len() as u64);
            let _ = syscall1(SYS_EXIT, 0);
        }
    } else {
        unsafe {
            let msg = b"USERLAND SELF-TEST FAIL\n";
            let _ = syscall3(SYS_WRITE, STDOUT_FD, msg.as_ptr() as u64, msg.len() as u64);
            let _ = syscall1(SYS_EXIT, 1);
        }
    }

    loop {
        unsafe {
            asm!("pause", options(nomem, nostack, preserves_flags));
        }
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
    unsafe {
        let msg = b"USERLAND SELF-TEST PANIC\n";
        let _ = syscall3(SYS_WRITE, STDOUT_FD, msg.as_ptr() as u64, msg.len() as u64);
        let _ = syscall1(SYS_EXIT, 1);
    }

    loop {
        unsafe {
            asm!("pause", options(nomem, nostack, preserves_flags));
        }
    }
}
