//! CPU mechanisms selected at compile time. Product and device policy do not
//! belong here; shared kernel code must not depend on an instruction set.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
mod selected;

#[cfg(target_arch = "aarch64")]
#[path = "aarch64/mod.rs"]
mod selected;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("mnu does not yet provide CPU primitives for this architecture");

pub use selected::context;
pub use selected::exception;

pub mod interrupts;
pub use selected::{stack_pointer, wait_for_interrupt};

/// Stop this CPU without allowing normal interrupt handlers to resume work.
pub fn halt() -> ! {
    interrupts::disable();
    loop {
        wait_for_interrupt();
    }
}
