//! Fallible native allocation, kept separate from the portable I/O gate.
use alloc::sync::Arc;

pub(crate) fn new_lock() -> Result<super::object_io::IoLock, u64> {
    Arc::try_new(super::object_io::State::new(|waiter| {
        crate::task::wake_registered_waiter(crate::task::ThreadId::from_u64(waiter));
    }))
    .map(super::object_io::IoLock::from_allocated)
    .map_err(|_| crate::syscall::ENOMEM)
}
