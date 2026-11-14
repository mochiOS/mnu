//! x86_64 implementations of the shared CPU mechanisms.

pub mod interrupts {
    pub use x86_64::instructions::interrupts::{are_enabled, disable, enable};
}

/// Wait for a CPU interrupt. The caller owns the interrupt-mask policy.
#[inline]
pub fn wait_for_interrupt() {
    x86_64::instructions::hlt();
}

#[inline]
pub fn stack_pointer() -> u64 {
    let value;
    // SAFETY: Reading RSP neither changes the stack nor accesses memory.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}
