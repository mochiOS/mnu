//! x86_64 implementations of the shared CPU mechanisms.

pub mod context;
pub mod counter;
pub mod exception;
#[cfg(not(mnu_arch_probe))]
pub mod memory;

pub mod interrupts {
    use core::arch::asm;

    #[inline]
    pub fn are_enabled() -> bool {
        let flags: u64;
        // SAFETY: The balanced push/pop reads RFLAGS without changing it.
        unsafe {
            asm!("pushfq", "pop {}", out(reg) flags, options(nomem, preserves_flags));
        }
        flags & (1 << 9) != 0
    }

    #[inline]
    pub fn disable() {
        // SAFETY: Executed at kernel privilege. Keep a compiler memory barrier
        // just as the previous x86_64 crate implementation did.
        unsafe {
            asm!("cli", options(nostack, preserves_flags));
        }
    }

    #[inline]
    pub fn enable() {
        // SAFETY: The kernel controls the local CPU's interrupt flag.
        unsafe {
            asm!("sti", options(nostack, preserves_flags));
        }
    }
}

/// Wait for a CPU interrupt. The caller owns the interrupt-mask policy.
#[inline]
pub fn wait_for_interrupt() {
    // SAFETY: Executed by the privileged kernel; the caller owns IF policy.
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
    }
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
