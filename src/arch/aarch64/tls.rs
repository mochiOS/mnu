//! Variant-I user thread pointer, independent of EL1 CPU-local state.
use core::arch::asm;

/// # Safety
/// Run at EL1 on the selected thread's CPU. The caller must validate `base`
/// against that thread's userspace address space and exclude scheduling.
pub unsafe fn write_user_base(base: u64) {
    // SAFETY: Only this CPU's EL0-visible TLS register is updated. EL1's
    // TPIDR_EL1 and exception stack are never taken from a userspace value.
    unsafe {
        asm!("msr tpidr_el0, {}", in(reg) base, options(nostack, preserves_flags));
    }
}

/// # Safety
/// Run at EL1 on the thread's CPU, excluding migration and context changes.
pub unsafe fn read_user_base() -> u64 {
    let value;
    // SAFETY: Reading TLS does not dereference the user-controlled address.
    unsafe {
        asm!("mrs {}, tpidr_el0", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}
