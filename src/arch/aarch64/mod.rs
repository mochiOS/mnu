//! AArch64 CPU primitives for a privileged kernel. Controller discovery,
//! interrupt routing and exception-vector installation are separate work.

pub mod context;
pub mod counter;
pub mod hypercall;
pub mod exception;
pub mod fp;
pub mod tls;
pub mod memory;
pub mod paging;
pub mod usermode;

pub mod interrupts {
    use core::arch::asm;

    /// Whether normal IRQ exceptions are unmasked (PSTATE.I == 0).
    /// Debug, SError and FIQ masks are deliberately left unchanged.
    #[inline]
    pub fn are_enabled() -> bool {
        let daif: u64;
        // SAFETY: DAIF is read at the kernel's privileged exception level.
        unsafe {
            asm!("mrs {}, daif", out(reg) daif, options(nomem, nostack, preserves_flags));
        }
        daif & (1 << 7) == 0
    }

    #[inline]
    pub fn disable() {
        // SAFETY: Only the current CPU's IRQ mask is changed. Omitting nomem
        // prevents compiler movement of accesses across this critical boundary.
        unsafe {
            asm!("msr daifset, #2", options(nostack, preserves_flags));
        }
    }

    #[inline]
    pub fn enable() {
        // SAFETY: The kernel controls the current CPU's IRQ mask. Other DAIF
        // fields, privilege level and return context are not modified.
        unsafe {
            asm!("msr daifclr, #2", options(nostack, preserves_flags));
        }
    }
}

/// Wait for a CPU interrupt; wakeups can be spurious, so callers recheck work.
/// Does not enable IRQs or replace the scheduler's lost-wakeup protocol.
#[inline]
pub fn wait_for_interrupt() {
    // SAFETY: WFI is executed by the privileged kernel. No pointers are used.
    unsafe {
        core::arch::asm!("wfi", options(nostack, preserves_flags));
    }
}

#[inline]
pub fn stack_pointer() -> u64 {
    let value;
    // SAFETY: Reading SP does not change the active stack or access memory.
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}
