use core::arch::asm;
use mnu_abi::hypervisor::{
    HypercallNumber, ShutdownReason, HYPERVISOR_BACKEND_AMD_SVM, HYPERVISOR_BACKEND_INTEL_VMX,
};

pub unsafe fn invoke(
    backend: u32,
    number: HypercallNumber,
    arg0: u64,
    arg1: u64,
    arg2: u64,
) -> u64 {
    let mut result = number as u64;
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

#[allow(dead_code)]
pub fn shutdown(backend: u32, reason: ShutdownReason) -> ! {
    let _ = unsafe { invoke(backend, HypercallNumber::Shutdown, reason as u64, 0, 0) };
    halt_forever()
}

pub fn halt_forever() -> ! {
    loop {
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}
