use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};
use mnu_abi::hypervisor::{
    HypercallNumber, HYPERVISOR_BACKEND_AMD_SVM, HYPERVISOR_BACKEND_INTEL_VMX,
};

static BACKEND: AtomicU32 = AtomicU32::new(0);

pub fn configure(backend: u32) -> bool {
    if !matches!(
        backend,
        HYPERVISOR_BACKEND_INTEL_VMX | HYPERVISOR_BACKEND_AMD_SVM
    ) {
        return false;
    }
    BACKEND.store(backend, Ordering::Release);
    true
}

pub fn is_active() -> bool {
    BACKEND.load(Ordering::Acquire) != 0
}

/// Returns the virtual TSC frequency advertised by mBoot, in kHz.
pub fn tsc_frequency_khz() -> u32 {
    if !is_active() {
        return 0;
    }
    let eax = 0x4000_0001u32;
    let ebx: u64;
    unsafe {
        core::arch::asm!(
            "mov {saved:r}, rbx",
            "cpuid",
            "xchg {saved:r}, rbx",
            saved = inout(reg) 0u64 => ebx,
            inout("eax") eax => _,
            out("ecx") _,
            out("edx") _,
            options(nomem, nostack)
        );
    }
    ebx as u32
}

pub fn invoke(number: HypercallNumber, arg0: u64, arg1: u64, arg2: u64) -> u64 {
    let mut result = number as u64;
    unsafe {
        match BACKEND.load(Ordering::Acquire) {
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
