//! CPU-owned access to the current userspace thread pointer.
use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

static FSGSBASE: AtomicBool = AtomicBool::new(false);

/// Called during CPU initialization, before enabling the CR4 fast path.
pub fn detect_fsgsbase() {
    let supported = core::arch::x86_64::__cpuid_count(7, 0).ebx & 1 != 0;
    FSGSBASE.store(supported, Ordering::Release);
}

pub fn uses_fsgsbase() -> bool {
    FSGSBASE.load(Ordering::Acquire)
}

/// # Safety
/// Run at kernel privilege on a CPU initialized by mnu. `base` must be the
/// validated canonical TLS address of the selected userspace thread.
pub unsafe fn write_user_base(base: u64) {
    if uses_fsgsbase() {
        // SAFETY: CPU initialization detects support and enables CR4.FSGSBASE.
        unsafe {
            asm!("wrfsbase {}", in(reg) base, options(nostack, preserves_flags));
        }
    } else {
        // SAFETY: IA32_FS_BASE is available at kernel privilege on x86_64.
        unsafe {
            asm!("wrmsr", in("ecx") 0xC000_0100u32, in("eax") base as u32,
                in("edx") (base >> 32) as u32, options(nomem, nostack, preserves_flags));
        }
    }
}

/// # Safety
/// Run at kernel privilege on a CPU initialized by mnu, excluding migration.
pub unsafe fn read_user_base() -> u64 {
    if uses_fsgsbase() {
        let value;
        // SAFETY: The per-CPU initialization contract enables this instruction.
        unsafe {
            asm!("rdfsbase {}", out(reg) value, options(nostack, preserves_flags));
        }
        value
    } else {
        let lo: u32;
        let hi: u32;
        // SAFETY: IA32_FS_BASE is read-only here, at kernel privilege.
        unsafe {
            asm!("rdmsr", in("ecx") 0xC000_0100u32, out("eax") lo,
                out("edx") hi, options(nomem, nostack, preserves_flags));
        }
        (u64::from(hi) << 32) | u64::from(lo)
    }
}
