//! Bounded ownership for deferred native work. This is not an executor: the
//! caller supplies synchronization and an execution context. No I/O, wakeup,
//! payload destruction or allocation is performed while editing queue slots.
use alloc::sync::Arc;
use mnu_abi::status::Error;

struct Value<T>(Option<T>);

/// Allocate before taking a queue lock. Failure returns the original payload.
pub(crate) struct Prepared<T>(Arc<Value<T>>);

impl<T> Prepared<T> {
    pub(crate) fn value(&self) -> &T { self.0.0.as_ref().unwrap() }
    pub(crate) fn new(value: T) -> Result<Self, (Error, T)> {
        let mut storage = match Arc::try_new(Value(None)) {
            Ok(storage) => storage,
            Err(_) => return Err((Error::ResourceUnavailable, value)),
        };
        // No other reference exists before publication.
        Arc::get_mut(&mut storage).unwrap().0 = Some(value);
        Ok(Self(storage))
    }

    /// Only an unpublished/rejected owner may be recovered. Queue/claim code
    /// never hands out another Prepared for an admitted job.
    pub(crate) fn into_value(self) -> T {
        match Arc::try_unwrap(self.0) {
            Ok(mut storage) => storage.0.take().unwrap(),
            Err(_) => unreachable!("prepared work is not published"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Queued,
    Running,
    Failed(u64),
}

struct Entry<T> {
    work: Prepared<T>,
    sequence: u64,
    phase: Phase,
}

/// An owned reference for execution outside the queue lock. It cannot be
/// cloned, and the queue retains its own reference until explicit retirement.
pub(crate) struct Claim<T> {
    slot: usize,
    work: Arc<Value<T>>,
}

impl<T> Claim<T> {
    pub(crate) fn value(&self) -> &T {
        self.work.0.as_ref().unwrap()
    }
}

/// Return both owners on success so the caller can drop them AFTER unlocking.
pub(crate) struct Retired<T> {
    _entry: Entry<T>,
    _claim: Claim<T>,
}

pub(crate) enum Completion<T> {
    Retired(Retired<T>),
    Failed { error: u64, claim: Claim<T> },
}

/// Capacity includes queued, running and failed work. A failed operation is
/// never silently retried or discarded. In particular, losing a worker claim
/// does not free a slot or the resources which that operation may still use.
pub(crate) struct Queue<T, const N: usize> {
    entries: [Option<Entry<T>>; N],
    next_sequence: u64,
}

impl<T, const N: usize> Queue<T, N> {
    pub(crate) const fn new() -> Self {
        Self {
            entries: [const { None }; N],
            next_sequence: 0,
        }
    }

    pub(crate) fn submit(&mut self, work: Prepared<T>) -> Result<(), (Error, Prepared<T>)> {
        let Some(slot) = self.entries.iter_mut().find(|entry| entry.is_none()) else {
            return Err((Error::ResourceUnavailable, work));
        };
        let Some(next) = self.next_sequence.checked_add(1) else {
            return Err((Error::LimitExceeded, work));
        };
        *slot = Some(Entry {
            work,
            sequence: self.next_sequence,
            phase: Phase::Queued,
        });
        self.next_sequence = next;
        Ok(())
    }

    pub(crate) fn claim(&mut self) -> Option<Claim<T>> {
        let slot = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.as_ref().is_some_and(|e| e.phase == Phase::Queued))
            .min_by_key(|(_, entry)| entry.as_ref().unwrap().sequence)?
            .0;
        let entry = self.entries[slot].as_mut().unwrap();
        entry.phase = Phase::Running;
        Some(Claim {
            slot,
            work: Arc::clone(&entry.work.0),
        })
    }

    fn entry_for(&mut self, claim: &Claim<T>) -> Option<&mut Entry<T>> {
        self.entries
            .get_mut(claim.slot)?
            .as_mut()
            .filter(|entry| Arc::ptr_eq(&entry.work.0, &claim.work))
    }

    pub(crate) fn complete(
        &mut self,
        claim: Claim<T>,
        result: Result<(), u64>,
    ) -> Result<Completion<T>, Claim<T>> {
        let Some(entry) = self.entry_for(&claim) else {
            return Err(claim);
        };
        if entry.phase != Phase::Running {
            return Err(claim);
        }
        if let Err(error) = result {
            entry.phase = Phase::Failed(error);
            return Ok(Completion::Failed { error, claim });
        }
        let entry = self.entries[claim.slot].take().unwrap();
        Ok(Completion::Retired(Retired {
            _entry: entry,
            _claim: claim,
        }))
    }

    /// Retire a quiescent failure only when its owner explicitly acknowledges
    /// the error. Return both references so backing cleanup stays outside the
    /// queue lock. Running work cannot be cancelled through this operation.
    pub(crate) fn acknowledge_failure(
        &mut self,
        claim: Claim<T>,
    ) -> Result<(u64, Retired<T>), Claim<T>> {
        let Some(entry) = self.entry_for(&claim) else {
            return Err(claim);
        };
        let Phase::Failed(error) = entry.phase else {
            return Err(claim);
        };
        let entry = self.entries[claim.slot].take().unwrap();
        Ok((
            error,
            Retired {
                _entry: entry,
                _claim: claim,
            },
        ))
    }

    /// Only the matching failed claim can request a retry. No fresh user
    /// address, process identity, or resource lookup participates in retry.
    pub(crate) fn retry(&mut self, claim: Claim<T>) -> Result<(), Claim<T>> {
        let Some(next) = self.next_sequence.checked_add(1) else {
            return Err(claim);
        };
        let sequence = self.next_sequence;
        let Some(entry) = self.entry_for(&claim) else {
            return Err(claim);
        };
        if !matches!(entry.phase, Phase::Failed(_)) {
            return Err(claim);
        }
        // Preserve the queue's owner; releasing the claim cannot destroy T.
        entry.sequence = sequence;
        self.next_sequence = next;
        self.entries[claim.slot].as_mut().unwrap().phase = Phase::Queued;
        Ok(())
    }
}
