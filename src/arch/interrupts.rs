//! Local maskable interrupt control. This is not an inter-CPU memory barrier.

pub use super::selected::interrupts::{are_enabled, disable, enable};

/// Run a closure with local interrupts disabled, retaining the entry state.
/// The closure must not enable interrupts itself. Nested calls are supported.
#[inline]
pub fn without_interrupts<F: FnOnce() -> R, R>(f: F) -> R {
    let enabled = are_enabled();
    if enabled {
        disable();
    }
    let result = f();
    if enabled {
        enable();
    }
    result
}
