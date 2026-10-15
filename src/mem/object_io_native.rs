//! Fallible native allocation, kept separate from the portable I/O gate.
use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;

pub(crate) fn new_lock() -> Result<super::object_io::IoLock, u64> {
    Arc::try_new(AtomicBool::new(false))
        .map(super::object_io::IoLock::from_allocated)
        .map_err(|_| crate::syscall::ENOMEM)
}
