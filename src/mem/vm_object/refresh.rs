//! Cache half of a backing refresh transaction. This alone does NOT authorize
//! refreshing live mappings: the coordinator must suspend affected PTEs and
//! acknowledge remote TLBs before writeback, then retain that journal through
//! publication/rollback. No POSIX flags or caller addresses are stored here.
use super::*;

pub(crate) struct PreparedRefresh {
    object: VmObject,
    start: u64,
    end: u64,
    epoch: u64,
    gate: super::super::object_io::IoLock,
    _reservation: super::super::object_io::Reservation,
    flushed: bool,
    published: bool,
}

impl VmObject {
    /// The coordinator holds VM exclusion while preparing. This never waits:
    /// active I/O returns NotReady without changing mappings/cache/epochs.
    pub(crate) fn prepare_refresh(&self, start: u64, length: u64) -> Result<PreparedRefresh, u64> {
        if length == 0 || (start | length) & (PAGE_BYTES as u64 - 1) != 0 {
            return Err(Error::InvalidArgument.into_raw());
        }
        let end = start
            .checked_add(length)
            .ok_or(Error::InvalidArgument.into_raw())?;
        let VmObjectSource::Provider { _io_lock: gate, .. } = &self.source else {
            return Err(Error::InvalidArgument.into_raw());
        };
        let guard = gate
            .try_lock()
            .map_err(|_| Error::BackingFailure.into_raw())?
            .ok_or(Error::NotReady.into_raw())?;
        // Share exclusion with fault publication, as in extent preparation.
        let cache = PAGE_CACHE.lock();
        let reservation = guard.reserve();
        let epoch = gate.generation();
        drop(cache);
        Ok(PreparedRefresh {
            object: self.clone(),
            start,
            end,
            epoch,
            gate: gate.clone(),
            _reservation: reservation,
            flushed: false,
            published: false,
        })
    }
}

impl PreparedRefresh {
    pub(crate) fn range(&self) -> (u64, u64) {
        (self.start, self.end)
    }
    pub(crate) fn preflight(&self) -> Result<(), u64> {
        self.check()
    }

    fn check(&self) -> Result<(), u64> {
        if self.published {
            return Err(Error::InvalidArgument.into_raw());
        }
        if self.gate.is_unavailable() {
            return Err(Error::BackingFailure.into_raw());
        }
        if !self.gate.is_reserved() || self.gate.generation() != self.epoch {
            return Err(Error::NotReady.into_raw());
        }
        Ok(())
    }

    /// Only after suspending affected writable aliases and all-CPU TLB ack.
    /// No VM lock is retained here. Failure leaves cache data/dirty ranges
    /// intact for rollback/retry, including partially written lower storage.
    pub(crate) fn writeback(&mut self) -> Result<(), u64> {
        self.check()?;
        self.flushed = false;
        self.object.flush_provider_range(self.start, self.end)?;
        self.flushed = true;
        Ok(())
    }

    /// The coordinator holds VM exclusion and validates its retained PTE
    /// records first. All fallible checks precede cache mutation. Keep this
    /// reservation alive until those records have been restored or released.
    /// Old fault preparations cannot publish into the refreshed cache epoch.
    pub(crate) fn publish(&mut self) -> Result<(), u64> {
        let mut cache = PAGE_CACHE.lock();
        self.check()?;
        if !self.flushed {
            return Err(Error::NotReady.into_raw());
        }
        let key = self.object.object_key();
        if cache
            .iter()
            .filter(|entry| entry.key.object == key)
            .any(|entry| {
                entry
                    .key
                    .page_index
                    .checked_mul(PAGE_BYTES as u64)
                    .is_none()
            })
        {
            return Err(Error::BackingFailure.into_raw());
        }
        cache.retain(|entry| {
            if entry.key.object != key {
                return true;
            }
            let offset = entry.key.page_index * PAGE_BYTES as u64;
            offset < self.start || offset >= self.end
        });
        bump_cache_mutation_epoch(key);
        self.published = true;
        Ok(())
    }
}
