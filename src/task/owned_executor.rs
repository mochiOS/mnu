//! Submission/completion bridge for an explicitly installed native executor.
//! The execution context and wake callbacks belong to the caller. This module
//! neither spawns threads nor interprets services, paths or compatibility policy.
use super::owned_work::{Completion, Prepared, Queue};
use crate::interrupt::spinlock::SpinLock;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use mnu_abi::status::Error;

struct ResultState {
    phase: AtomicU8,
    error: AtomicU64,
}

/// Pending and a terminal failure with value zero are distinct. The status is
/// retained independently of the submitted payload and needs no allocation to
/// publish or read. Cloning this receipt grants no resource or queue authority.
#[derive(Clone)]
pub(crate) struct Receipt(Arc<ResultState>);

impl Receipt {
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
    }
}

struct Job<T> {
    value: T,
    receipt: Receipt,
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
        let worker = self.worker.load(Ordering::Acquire);
        if worker == 0 {
            return Err((Error::NotReady, value));
        }
        let receipt = match Arc::try_new(ResultState {
            phase: AtomicU8::new(0),
            error: AtomicU64::new(0),
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
        let admission = self.pending.lock().submit(prepared);
        if let Err((error, prepared)) = admission {
            // No queue reference was published, so the original job can be
            // recovered without cloning its resource or dropping under lock.
            return Err((error, prepared.into_value().value));
        }
        wake(worker);
        Ok(receipt)
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
