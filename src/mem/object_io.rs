use alloc::sync::{Arc, Weak};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::interrupt::spinlock::SpinLock;

struct Admission {
    locked: bool,
    next: u64,
    waiting: VecDeque<u64>,
}

impl Admission {
    const fn new() -> Self {
        Self {
            locked: false,
            next: 0,
            waiting: VecDeque::new(),
        }
    }
}

pub(crate) struct State {
    admission: SpinLock<Admission>,
    reserved: AtomicBool,
    unavailable: AtomicBool,
    generation: AtomicU64,
}

impl State {
    pub(crate) const fn new() -> Self {
        Self {
            admission: SpinLock::new(Admission::new()),
            reserved: AtomicBool::new(false),
            unavailable: AtomicBool::new(false),
            generation: AtomicU64::new(1),
        }
    }
}

/// Weak registrations do not outlive their backing or active I/O owners.
pub(crate) struct Registry<K> {
    gates: Vec<(K, Weak<State>)>,
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
        if let Some(gate) = self.existing(&key) {
            return Ok(gate);
        }
        self.gates.try_reserve(1).map_err(|_| allocation_error)?;
        let gate = create()?;
        self.gates.push((key, Arc::downgrade(&gate.0)));
        Ok(gate)
    }

    pub(crate) fn existing(&self, key: &K) -> Option<IoLock> {
        self.gates
            .iter()
            .find_map(|(existing, gate)| (existing == key).then(|| gate.upgrade()).flatten())
            .map(IoLock)
    }
}

#[derive(Clone)]
pub(crate) struct IoLock(Arc<State>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Unavailable;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntentError {
    Unavailable,
    NoMemory,
    Exhausted,
    Consumed,
}

impl IoLock {
    pub(crate) fn from_allocated(gate: Arc<State>) -> Self {
        Self(gate)
    }
    pub(crate) fn generation(&self) -> u64 {
        self.0.generation.load(Ordering::Acquire)
    }
    pub(crate) fn is_reserved(&self) -> bool {
        self.0.reserved.load(Ordering::Acquire)
    }
    pub(crate) fn is_unavailable(&self) -> bool {
        self.0.unavailable.load(Ordering::Acquire)
    }
    /// Caller serializes cache publication through its cache/VM lock.
    pub(crate) fn advance_generation(&self) {
        self.0.generation.fetch_add(1, Ordering::AcqRel);
    }
    /// A resource owner must not wait for an I/O caller that may itself be
    /// waiting for that owner's reply. Failed admission leaves ownership alone.
    pub(crate) fn try_lock(&self) -> Result<Option<IoGuard>, Unavailable> {
        if self.is_unavailable() {
            return Err(Unavailable);
        }
        let guard = {
            let mut admission = self.0.admission.lock();
            if admission.locked || !admission.waiting.is_empty() {
                None
            } else {
                admission.locked = true;
                Some(IoGuard(self.0.clone()))
            }
        };
        // An unavailable owner can release between the first check and
        // acquisition. Never turn that handoff into healthy I/O admission.
        if self.is_unavailable() {
            drop(guard);
            Err(Unavailable)
        } else {
            Ok(guard)
        }
    }

    /// Register an owned, cancellable place ahead of NEW ordinary I/O.
    /// Existing I/O is not interrupted and this call never waits for it.
    /// Keep the intent alive while serving outstanding provider calls; merely
    /// remembering contention without an owner would strand later callers.
    /// Failed registration leaves both admission and generation unchanged.
    pub(crate) fn intent(&self) -> Result<IoIntent, IntentError> {
        if self.is_unavailable() {
            return Err(IntentError::Unavailable);
        }
        let mut admission = self.0.admission.lock();
        if self.is_unavailable() {
            return Err(IntentError::Unavailable);
        }
        let ticket = admission.next;
        let next = ticket.checked_add(1).ok_or(IntentError::Exhausted)?;
        admission
            .waiting
            .try_reserve(1)
            .map_err(|_| IntentError::NoMemory)?;
        admission.waiting.push_back(ticket);
        admission.next = next;
        Ok(IoIntent {
            gate: self.clone(),
            ticket: Some(ticket),
        })
    }
    /// Waiting must cooperate with the scheduler; this is not an IRQ spinlock.
    pub(crate) fn lock(&self, mut wait: impl FnMut()) -> Result<IoGuard, Unavailable> {
        loop {
            if let Some(guard) = self.try_lock()? {
                return Ok(guard);
            }
            wait();
        }
    }
}

/// A queue position, not storage permission or a mapping reservation. No VM
/// state changes until the acquired IoGuard is explicitly reserved. Ordinary
/// I/O cannot barge ahead of an intent; intents themselves are FIFO. Dropping
/// one removes just that position, including cancellation in the middle.
pub(crate) struct IoIntent {
    gate: IoLock,
    ticket: Option<u64>,
}

impl IoIntent {
    /// Poll without sleeping/IPC and consume the position exactly once on
    /// success. All owner-death/cancellation paths can simply drop the intent.
    pub(crate) fn try_acquire(&mut self) -> Result<Option<IoGuard>, IntentError> {
        let ticket = self.ticket.ok_or(IntentError::Consumed)?;
        if self.gate.is_unavailable() {
            return Err(IntentError::Unavailable);
        }
        let mut admission = self.gate.0.admission.lock();
        if self.gate.is_unavailable() {
            return Err(IntentError::Unavailable);
        }
        if admission.locked || admission.waiting.front() != Some(&ticket) {
            return Ok(None);
        }
        admission.waiting.pop_front();
        admission.locked = true;
        self.ticket = None;
        Ok(Some(IoGuard(self.gate.0.clone())))
    }
}

impl Drop for IoIntent {
    fn drop(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            let mut admission = self.gate.0.admission.lock();
            if let Some(index) = admission.waiting.iter().position(|entry| *entry == ticket) {
                admission.waiting.remove(index);
            }
        }
    }
}

pub(crate) struct IoGuard(Arc<State>);

impl IoGuard {
    /// Caller holds its cache/publication lock while starting the reservation.
    /// Exclude new page admission and invalidate outstanding snapshots.
    pub(crate) fn reserve(self) -> Reservation {
        self.0.reserved.store(true, Ordering::Release);
        self.0.generation.fetch_add(1, Ordering::AcqRel);
        Reservation { guard: self }
    }
}

/// Excludes backing I/O and page publication until commit or cancellation.
pub(crate) struct Reservation {
    guard: IoGuard,
}

impl Reservation {
    /// Latch failure under the caller's cache/VM publication exclusion, after
    /// revoking mappings which must no longer expose this backing. Dropping
    /// the reservation releases admission, but never clears this failure.
    /// This primitive alone does not perform revocation or resolve storage I/O.
    pub(crate) fn mark_unavailable(&self) {
        if !self.guard.0.unavailable.swap(true, Ordering::AcqRel) {
            self.guard.0.generation.fetch_add(1, Ordering::AcqRel);
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.guard.0.reserved.store(false, Ordering::Release);
        // IoGuard drops afterward, so new I/O cannot enter a reserved backing.
    }
}

impl Drop for IoGuard {
    fn drop(&mut self) {
        self.0.admission.lock().locked = false;
    }
}
