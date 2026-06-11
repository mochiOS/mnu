#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 1;
const SYS_EXIT: u64 = 60;
const STDOUT_FD: u64 = 1;

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

fn write_str(s: &str) {
    unsafe {
        let _ = syscall3(SYS_WRITE, STDOUT_FD, s.as_ptr() as u64, s.len() as u64);
    }
}

fn exit(code: u64) -> ! {
    unsafe {
        let _ = syscall3(SYS_EXIT, code, 0, 0);
    }
    loop {
        unsafe {
            asm!("pause", options(nomem, nostack, preserves_flags));
        }
    }
}

#[inline(never)]
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

#[inline(never)]
fn run_self_test() -> bool {
    let digest = [0xAB; 32];
    let contract = user::LaunchContract::new(
        "core.service",
        "mnu",
        true,
        user::ManifestRole::CoreService,
        digest,
        user::InstallSource::Initfs,
    );
    bytes_eq(contract.package_id.as_bytes(), b"core.service")
        && bytes_eq(contract.publisher_id.as_bytes(), b"mnu")
        && contract.signature_trusted
        && contract.manifest_role == user::ManifestRole::CoreService
        && bytes_eq(&contract.file_digest, &digest)
        && contract.install_source == user::InstallSource::Initfs
        && contract.is_well_formed()
        && !user::LaunchContract::new(
            "",
            "",
            false,
            user::ManifestRole::Unknown,
            [0; 32],
            user::InstallSource::Unknown,
        )
        .is_well_formed()
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_str("userland self-test: start\n");

    let ok = run_self_test();

    if ok {
        write_str("USERLAND SELF-TEST PASS\n");
        exit(0);
    } else {
        write_str("USERLAND SELF-TEST FAIL\n");
        exit(1);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str("USERLAND SELF-TEST PANIC\n");
    exit(1);
}
