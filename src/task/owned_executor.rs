//! Submission/completion bridge for an explicitly installed native executor.
//! The execution context and wake callbacks belong to the caller. This module
//! neither spawns threads nor interprets services, paths or compatibility policy.
use super::owned_work::{Completion, Prepared, Queue};
use crate::interrupt::spinlock::SpinLock;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use mnu_abi::status::Error;

const MAX_WAITERS: usize = crate::task::ThreadQueue::MAX_THREADS;

struct ResultState {
    phase: AtomicU8,
    error: AtomicU64,
    waiters: SpinLock<[Option<(u64, usize)>; MAX_WAITERS]>,
}

/// Pending and a terminal failure with value zero are distinct. The status is
/// retained independently of the submitted payload and needs no allocation to
/// publish or read. Cloning this receipt grants no resource or queue authority.
#[derive(Clone)]
pub struct Receipt(Arc<ResultState>);

/// A subscription owns only a result reference, never execution authority.
/// Duplicate registrations by a thread are reference counted so removing one
/// wait item cannot remove another item's wakeup registration.
pub(crate) struct Subscription {
    receipt: Receipt,
    slot: usize,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let mut waiters = self.receipt.0.waiters.lock();
        if let Some((_, count)) = &mut waiters[self.slot] {
            *count -= 1;
            if *count == 0 {
                waiters[self.slot] = None;
            }
        }
    }
}

impl Receipt {
    pub(crate) fn is_same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    pub(crate) fn read_at(&self, offset: u64, output: &mut [u8]) -> usize {
        let bytes = mnu_abi::completion::encode(self.result());
        let Ok(offset) = usize::try_from(offset) else {
            return 0;
        };
        let Some(bytes) = bytes.get(offset..) else {
            return 0;
        };
        let count = bytes.len().min(output.len());
        output[..count].copy_from_slice(&bytes[..count]);
        count
    }

    /// The caller must recheck readiness before sleeping and use the native
    /// latched wake/sleep protocol. Registration and terminal publication share
    /// exclusion; a racing completion either wakes this thread or is observed
    /// here. No allocation is required after accepting the operation.
    pub(crate) fn subscribe(&self, thread: u64) -> Result<Option<Subscription>, Error> {
        if thread == 0 {
            return Err(Error::InvalidArgument);
        }
        let mut waiters = self.0.waiters.lock();
        if self.result().is_some() {
            return Ok(None);
        }
        let slot = match waiters
            .iter()
            .position(|entry| entry.is_some_and(|(id, _)| id == thread))
        {
            Some(slot) => slot,
            None => waiters
                .iter()
                .position(Option::is_none)
                .ok_or(Error::ResourceUnavailable)?,
        };
        let count = waiters[slot].map_or(0, |(_, count)| count);
        let count = count.checked_add(1).ok_or(Error::LimitExceeded)?;
        waiters[slot] = Some((thread, count));
        Ok(Some(Subscription {
            receipt: self.clone(),
            slot,
        }))
    }

    pub(crate) fn result(&self) -> Option<Result<(), u64>> {
        match self.0.phase.load(Ordering::Acquire) {
            0 => None,
            1 => Some(Ok(())),
            _ => Some(Err(self.0.error.load(Ordering::Relaxed))),
        }
    }

    fn publish(&self, result: Result<(), u64>) {
        let phase = match result {
            Ok(()) => 1,
            Err(error) => {
                self.0.error.store(error, Ordering::Relaxed);
                2
            }
        };
        self.0.phase.store(phase, Ordering::Release);
        let waiters = core::mem::replace(&mut *self.0.waiters.lock(), [None; MAX_WAITERS]);
        for (thread, _) in waiters.into_iter().flatten() {
            crate::task::wake_registered_waiter(crate::task::ThreadId::from_u64(thread));
        }
    }
}

struct Job<T> {
    value: T,
    receipt: Receipt,
}

/// Own all submission storage before entering a publication transaction.
pub(crate) struct Submission<T>(Prepared<Job<T>>);

impl<T> Submission<T> {
    pub(crate) fn receipt(&self) -> Receipt {
        self.0.value().receipt.clone()
    }
    pub(crate) fn into_value(self) -> T {
        self.0.into_value().value
    }
}

pub(crate) struct Executor<T, const N: usize> {
    worker: AtomicU64,
    pending: SpinLock<Queue<Job<T>, N>>,
}

impl<T, const N: usize> Executor<T, N> {
    pub(crate) const fn new() -> Self {
        Self {
            worker: AtomicU64::new(0),
            pending: SpinLock::new(Queue::new()),
        }
    }

    /// Internal bootstrap only: the caller must first create a persistent,
    /// schedulable worker. No user-provided identity is authenticated here.
    pub(crate) fn install_worker(&self, worker: u64) -> Result<(), Error> {
        if worker == 0 {
            return Err(Error::InvalidArgument);
        }
        self.worker
            .compare_exchange(0, worker, Ordering::Release, Ordering::Relaxed)
            .map(|_| ())
            .map_err(|_| Error::AlreadyExists)
    }

    /// The wake callback runs after publication and outside queue exclusion.
    /// All rejected submissions return the original value to its owner.
    pub(crate) fn submit(&self, value: T, wake: impl FnOnce(u64)) -> Result<Receipt, (Error, T)> {
        if self.worker.load(Ordering::Acquire) == 0 {
            return Err((Error::NotReady, value));
        }
        let submission = Self::prepare(value)?;
        let receipt = submission.receipt();
        match self.admit(submission) {
            Ok(worker) => {
                wake(worker);
                Ok(receipt)
            }
            Err((error, submission)) => Err((error, submission.into_value())),
        }
    }

    pub(crate) fn prepare(value: T) -> Result<Submission<T>, (Error, T)> {
        let receipt = match Arc::try_new(ResultState {
            phase: AtomicU8::new(0),
            error: AtomicU64::new(0),
            waiters: SpinLock::new([None; MAX_WAITERS]),
        }) {
            Ok(state) => Receipt(state),
            Err(_) => return Err((Error::ResourceUnavailable, value)),
        };
        let prepared = match Prepared::new(Job {
            value,
            receipt: receipt.clone(),
        }) {
            Ok(prepared) => prepared,
            Err((error, job)) => return Err((error, job.value)),
        };
        Ok(Submission(prepared))
    }

    /// Publication only: no allocation, destruction or wake callback. The
    /// caller wakes the returned worker after its outer transaction unlocks.
    pub(crate) fn admit(&self, submission: Submission<T>) -> Result<u64, (Error, Submission<T>)> {
        let worker = self.worker.load(Ordering::Acquire);
        if worker == 0 {
            return Err((Error::NotReady, submission));
        }
        let admission = self.pending.lock().submit(submission.0);
        match admission {
            Ok(()) => Ok(worker),
            Err((error, prepared)) => Err((error, Submission(prepared))),
        }
    }

    /// Called by the installed execution context, not by a syscall caller.
    /// The worker must use a latched wake/sleep protocol around an empty poll.
    pub(crate) fn run_one(
        &self,
        execute: impl FnOnce(&T) -> Result<(), u64>,
        notify: impl FnOnce(),
    ) -> bool {
        let claim = self.pending.lock().claim();
        let Some(claim) = claim else { return false };
        let receipt = claim.value().receipt.clone();
        let result = execute(&claim.value().value);
        let completion = self.pending.lock().complete(claim, result);
        let retired = match completion {
            Ok(Completion::Retired(retired)) => retired,
            Ok(Completion::Failed { error, claim }) => {
                // The worker has observed the terminal failure. Keep its
                // receipt alive while retiring the payload; publish once,
                // after cleanup, just as for a successful operation.
                debug_assert_eq!(result, Err(error));
                let acknowledged = self.pending.lock().acknowledge_failure(claim);
                match acknowledged {
                    Ok((_, retired)) => retired,
                    Err(_) => unreachable!("executor owns its claim"),
                }
            }
            Err(_) => unreachable!("executor owns its running claim"),
        };
        drop(retired);
        receipt.publish(result);
        notify();
        true
    }
}
