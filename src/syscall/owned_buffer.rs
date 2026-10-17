//! Bounded scratch storage with one cached allocation and independent active
//! owners. No allocation, usercopy, transport or payload destruction under lock.
use crate::interrupt::spinlock::SpinLock;
use alloc::vec::Vec;
use mnu_abi::status::Error;

pub(super) struct Pool {
    maximum: usize,
    cached: SpinLock<Vec<u8>>,
}

impl Pool {
    pub(super) const fn new(maximum: usize) -> Self {
        Self {
            maximum,
            cached: SpinLock::new(Vec::new()),
        }
    }

    pub(super) fn acquire(&self, length: usize) -> Result<Lease<'_>, Error> {
        if length > self.maximum {
            return Err(Error::LimitExceeded);
        }
        let bytes = core::mem::take(&mut *self.cached.lock());
        let mut lease = Lease { pool: self, bytes };
        lease
            .bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::ResourceUnavailable)?;
        lease.bytes.resize(length, 0);
        Ok(lease)
    }
}

pub(super) struct Lease<'a> {
    pool: &'a Pool,
    bytes: Vec<u8>,
}

impl Lease<'_> {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.bytes.clear();
        let retired = {
            let mut cached = self.pool.cached.lock();
            if self.bytes.capacity() > cached.capacity() {
                core::mem::replace(&mut *cached, core::mem::take(&mut self.bytes))
            } else {
                Vec::new()
            }
        };
        // Retire replaced/rejected allocations only after restoring IRQ state.
        drop(retired);
    }
}
