//! Lock-free bookkeeping for full user-translation invalidation on CPUs.
//! Architecture code performs the flush; this ledger never acknowledges on
//! dispatch alone and never knows process names, descriptors or POSIX policy.

use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct Rendezvous<const CPUS: usize> {
    sequence: AtomicU64,
    requested: [AtomicU64; CPUS],
    completed: [AtomicU64; CPUS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    InvalidCpu,
    Exhausted,
}

/// Bound to the publishing ledger, so acknowledgements from a different
/// coordinator cannot accidentally authorize reclaiming this request's pages.
pub(crate) struct Publication<'a, const CPUS: usize> {
    ledger: &'a Rendezvous<CPUS>,
    generation: u64,
    targets: u64,
}

impl<const CPUS: usize> Rendezvous<CPUS> {
    pub(crate) const fn new() -> Self {
        assert!(CPUS > 0 && CPUS <= 64);
        Self {
            sequence: AtomicU64::new(0),
            requested: [const { AtomicU64::new(0) }; CPUS],
            completed: [const { AtomicU64::new(0) }; CPUS],
        }
    }

    /// Publish only AFTER editing page tables, with backing frames retained.
    /// Include every CPU that can hold an old translation; architecture code
    /// must synchronize the CPU-online snapshot and new address-space entry.
    /// All requests require a FULL user-TLB flush, so later generations can
    /// safely coalesce earlier requests. This is not a range-invalidation API.
    pub(crate) fn publish(&self, targets: u64) -> Result<Publication<'_, CPUS>, Error> {
        if CPUS < 64 && targets >> CPUS != 0 {
            return Err(Error::InvalidCpu);
        }
        let generation = if targets == 0 {
            0
        } else {
            // AcqRel orders concurrent publishers' prior page-table edits.
            // Never wrap: a stale acknowledgement must not match a new round.
            self.sequence
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| Error::Exhausted)?
                + 1
        };
        for cpu in 0..CPUS {
            if targets & (1u64 << cpu) != 0 {
                self.requested[cpu].fetch_max(generation, Ordering::Release);
            }
        }
        Ok(Publication {
            ledger: self,
            generation,
            targets,
        })
    }

    /// Run on the target CPU, with its context stable during the full flush.
    /// No locks/allocations are taken, allowing interrupt-disabled lock waiters
    /// to cooperate with shootdown instead of waiting for a maskable interrupt.
    pub(crate) fn service<E>(
        &self,
        cpu: usize,
        flush: impl FnOnce() -> Result<(), E>,
    ) -> Result<bool, ServiceError<E>> {
        let requested = self.requested.get(cpu).ok_or(ServiceError::InvalidCpu)?;
        let generation = requested.load(Ordering::Acquire);
        if self.completed[cpu].load(Ordering::Acquire) >= generation {
            return Ok(false);
        }
        flush().map_err(ServiceError::Flush)?;
        // A newer request arriving during the callback needs another flush.
        // A late/reentrant completion must never move acknowledgement backward.
        self.completed[cpu].fetch_max(generation, Ordering::Release);
        Ok(true)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ServiceError<E> {
    InvalidCpu,
    Flush(E),
}

impl<const CPUS: usize> Publication<'_, CPUS> {
    /// True only after all target CPUs have completed a full flush ordered
    /// after publication. Backing must remain retained while this is false.
    pub(crate) fn complete(&self) -> bool {
        (0..CPUS).all(|cpu| {
            self.targets & (1u64 << cpu) == 0
                || self.ledger.completed[cpu].load(Ordering::Acquire) >= self.generation
        })
    }
}
