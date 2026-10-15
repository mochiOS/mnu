use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

/// Weak registrations do not outlive their backing or active I/O owners.
pub(crate) struct Registry<K> {
    gates: Vec<(K, Weak<AtomicBool>)>,
}

impl<K: PartialEq> Registry<K> {
    pub(crate) const fn new() -> Self {
        Self { gates: Vec::new() }
    }

    /// Reuse a live backing's gate without allocation. Construct and register
    /// a new gate only after reserving its weak-registration slot.
    pub(crate) fn try_get<E>(
        &mut self,
        key: K,
        create: impl FnOnce() -> Result<IoLock, E>,
        allocation_error: E,
    ) -> Result<IoLock, E> {
        self.gates.retain(|(_, gate)| gate.strong_count() != 0);
        if let Some(gate) = self
            .gates
            .iter()
            .find_map(|(existing, gate)| (existing == &key).then(|| gate.upgrade()).flatten())
        {
            return Ok(IoLock(gate));
        }
        self.gates.try_reserve(1).map_err(|_| allocation_error)?;
        let gate = create()?;
        self.gates.push((key, Arc::downgrade(&gate.0)));
        Ok(gate)
    }
}

#[derive(Clone)]
pub(crate) struct IoLock(Arc<AtomicBool>);

impl IoLock {
    pub(crate) fn from_allocated(gate: Arc<AtomicBool>) -> Self {
        Self(gate)
    }
    /// Waiting must cooperate with the scheduler; this is not an IRQ spinlock.
    pub(crate) fn lock(&self, mut wait: impl FnMut()) -> IoGuard {
        while self
            .0
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            wait();
        }
        IoGuard(self.0.clone())
    }
}

pub(crate) struct IoGuard(Arc<AtomicBool>);

impl Drop for IoGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
