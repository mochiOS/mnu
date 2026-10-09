use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

/// Weak registrations avoid retaining resources once all active I/O ends.
pub(crate) struct Registry<K> {
    gates: Vec<(K, Weak<AtomicBool>)>,
}

impl<K: PartialEq> Registry<K> {
    pub(crate) const fn new() -> Self {
        Self { gates: Vec::new() }
    }

    pub(crate) fn get(&mut self, key: K) -> IoLock {
        self.gates.retain(|(_, gate)| gate.strong_count() != 0);
        if let Some(gate) = self
            .gates
            .iter()
            .find_map(|(existing, gate)| (existing == &key).then(|| gate.upgrade()).flatten())
        {
            return IoLock(gate);
        }
        let gate = Arc::new(AtomicBool::new(false));
        self.gates.push((key, Arc::downgrade(&gate)));
        IoLock(gate)
    }
}

#[derive(Clone)]
pub(crate) struct IoLock(Arc<AtomicBool>);

impl IoLock {
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
