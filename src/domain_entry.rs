#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;
use mnu_abi::hypervisor::{
    DomainBootInfo, HypercallNumber, ShutdownReason, HYPERVISOR_BACKEND_AMD_SVM,
    HYPERVISOR_BACKEND_INTEL_VMX,
};

static START_MESSAGE: &[u8] = b"mnu entered its mBoot Domain\n";

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.domain_entry")]
pub unsafe extern "sysv64" fn domain_entry(boot_info_ptr: *const DomainBootInfo) -> ! {
    let Some(boot_info) = (unsafe { boot_info_ptr.as_ref() }) else {
        invalid_boot_info(HYPERVISOR_BACKEND_AMD_SVM)
    };
    if boot_info.validate().is_err() {
        invalid_boot_info(boot_info.hypervisor_backend)
    }

    let _ = unsafe {
        hypercall(
            boot_info.hypervisor_backend,
            HypercallNumber::ConsoleWrite,
            START_MESSAGE.as_ptr() as u64,
            START_MESSAGE.len() as u64,
            0,
        )
    };
    let _ = unsafe {
        hypercall(
            boot_info.hypervisor_backend,
            HypercallNumber::Yield,
            0,
            0,
            0,
        )
    };
    let _ = unsafe {
        hypercall(
            boot_info.hypervisor_backend,
            HypercallNumber::Shutdown,
            ShutdownReason::Completed as u64,
            0,
            0,
        )
    };
    halt_forever()
}

fn invalid_boot_info(backend: u32) -> ! {
    if matches!(
        backend,
        HYPERVISOR_BACKEND_INTEL_VMX | HYPERVISOR_BACKEND_AMD_SVM
    ) {
        // SAFETY: The caller supplied the instruction selected by mBoot.
        let _ = unsafe {
            hypercall(
                backend,
                HypercallNumber::Shutdown,
                ShutdownReason::InvalidBootInfo as u64,
                0,
                0,
            )
        };
    }
    halt_forever()
}

unsafe fn hypercall(backend: u32, number: HypercallNumber, arg0: u64, arg1: u64, arg2: u64) -> u64 {
    let mut result = number as u64;
    // SAFETY: This binary executes only as a guest of the backend named in its
    // validated DomainBootInfo. The register convention is part of mnu-abi.
    unsafe {
        match backend {
            HYPERVISOR_BACKEND_INTEL_VMX => asm!(
                "vmcall",
                inout("rax") result,
                inlateout("rdi") arg0 => _,
                inlateout("rsi") arg1 => _,
                inlateout("rdx") arg2 => _,
                clobber_abi("sysv64"),
                options(nostack)
            ),
            HYPERVISOR_BACKEND_AMD_SVM => asm!(
                "vmmcall",
                inout("rax") result,
                inlateout("rdi") arg0 => _,
                inlateout("rsi") arg1 => _,
                inlateout("rdx") arg2 => _,
                clobber_abi("sysv64"),
                options(nostack)
            ),
            _ => return u64::MAX,
        }
    }
    result
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: There is no recoverable path after Domain shutdown.
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    halt_forever()
}
