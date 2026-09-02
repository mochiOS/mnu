use core::arch::asm;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use mnu_abi::hypervisor::{
    DomainBootInfo, HypercallNumber, HYPERVISOR_BACKEND_AMD_SVM, HYPERVISOR_BACKEND_INTEL_VMX,
};

static BACKEND: AtomicU32 = AtomicU32::new(0);
static DOMAIN_ID: AtomicU32 = AtomicU32::new(0);
static FEATURE_FLAGS: AtomicU64 = AtomicU64::new(0);
static GRANT_WINDOW_START: AtomicU64 = AtomicU64::new(0);
static GRANT_WINDOW_SIZE: AtomicU64 = AtomicU64::new(0);

pub fn configure(info: &DomainBootInfo) -> bool {
    let backend = info.hypervisor_backend;
    if !matches!(
        backend,
        HYPERVISOR_BACKEND_INTEL_VMX | HYPERVISOR_BACKEND_AMD_SVM
    ) {
        return false;
    }
    DOMAIN_ID.store(info.domain_id, Ordering::Release);
    FEATURE_FLAGS.store(info.feature_flags, Ordering::Release);
    GRANT_WINDOW_START.store(info.grant_window_start, Ordering::Release);
    GRANT_WINDOW_SIZE.store(info.grant_window_size, Ordering::Release);
    BACKEND.store(backend, Ordering::Release);
    true
}

pub fn is_active() -> bool {
    BACKEND.load(Ordering::Acquire) != 0
}

pub fn domain_id() -> u32 {
    DOMAIN_ID.load(Ordering::Acquire)
}

pub fn feature_flags() -> u64 {
    FEATURE_FLAGS.load(Ordering::Acquire)
}

pub fn grant_window() -> Option<(u64, u64)> {
    let start = GRANT_WINDOW_START.load(Ordering::Acquire);
    let size = GRANT_WINDOW_SIZE.load(Ordering::Acquire);
    (start != 0 && size != 0).then_some((start, size))
}

/// Returns the virtual TSC frequency advertised by the hypervisor, in kHz.
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
