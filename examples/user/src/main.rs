#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = mnu_abi::SyscallNumber::Write as u64;
const SYS_EXIT: u64 = mnu_abi::SyscallNumber::Exit as u64;
const STDOUT_FD: u64 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_line("raw syscall write: start");
    let pass = user::run_self_test();

    if pass {
        write_line("USERLAND SELF-TEST PASS");
        unsafe { let _ = syscall1(SYS_EXIT, 0); }
    } else {
        write_line("USERLAND SELF-TEST FAIL");
        unsafe { let _ = syscall1(SYS_EXIT, 1); }
    }

    loop {
        unsafe {
            asm!("pause", options(nomem, nostack, preserves_flags));
        }
    }
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
