//! Serialize authority mutation with the final phase of an image commit.
//! The state lives in the existing process object; admission never allocates.
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use mnu_abi::status::Error;

use super::{process::ProcessObject, ProcessId};

const FROZEN: u64 = 1 << 63;

#[derive(Debug)]
pub(crate) struct Activity(AtomicU64);

impl Activity {
    pub(crate) const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    fn begin_mutation(&self) -> bool {
        let mut current = self.0.load(Ordering::Acquire);
        loop {
            if current >= FROZEN - 1 {
                return false;
            }
            match self.0.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn begin_commit(&self) -> bool {
        self.0
            .compare_exchange(0, FROZEN, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

pub(crate) struct Mutation(Arc<ProcessObject>);
pub(crate) struct Commit(Arc<ProcessObject>);

/// Retain the process object, then acquire outside the process-table borrow.
/// Busy final commits are retryable; never wait while holding that table.
pub(crate) fn begin_mutation(process: ProcessId) -> Result<Mutation, Error> {
    let owner =
        super::with_process(process, |process| process.process_object()).ok_or(Error::NotReady)?;
    if !owner.authority_activity().begin_mutation() {
        return Err(Error::ResourceUnavailable);
    }
    Ok(Mutation(owner))
}

pub(crate) fn begin_commit(process: ProcessId) -> Result<Commit, Error> {
    let owner =
        super::with_process(process, |process| process.process_object()).ok_or(Error::NotReady)?;
    if !owner.authority_activity().begin_commit() {
        return Err(Error::ResourceUnavailable);
    }
    Ok(Commit(owner))
}

impl Drop for Mutation {
    fn drop(&mut self) {
        self.0
            .authority_activity()
            .0
            .fetch_sub(1, Ordering::Release);
    }
}

impl Drop for Commit {
    fn drop(&mut self) {
        self.0.authority_activity().0.store(0, Ordering::Release);
    }
}
