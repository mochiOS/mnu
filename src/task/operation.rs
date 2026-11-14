//! Resources owned by an executing thread, including across kernel waits.
//!
//! A forced exit discards the kernel stack without running its destructors.
//! Keep the sole owning allocation in the thread instead. A local Scope is a
//! non-Send borrow; it detaches the owner on normal return. Thread retirement
//! drops owners only after CPU quiescence and outside the thread-queue lock.
use alloc::boxed::Box;
use core::any::Any;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use mnu_abi::status::Error;

pub(super) struct Owned {
    address: usize,
    _storage: Box<dyn Any + Send>,
}

impl Owned {
    pub(super) fn address(&self) -> usize {
        self.address
    }
}

// The identity byte gives even zero-sized payloads a unique allocation.
struct Slot<T> {
    value: T,
    _identity: u8,
}

#[must_use]
pub(crate) struct Scope<T> {
    owner: super::ThreadId,
    slot: NonNull<Slot<T>>,
}

impl<T: Send + 'static> Scope<T> {
    /// Keep the sole owner reachable from thread retirement while the callback
    /// may park. The callback borrows the value instead of keeping a stack owner.
    pub(crate) fn with<R>(value: T, body: impl FnOnce(&T) -> R) -> Result<R, Error> {
        let held = Self::new(value)?;
        Ok(body(&held))
    }

    pub(crate) fn new(value: T) -> Result<Self, Error> {
        let owner = super::current_thread_id().ok_or(Error::NotReady)?;
        let mut storage = Box::try_new(Slot {
            value,
            _identity: 0,
        })
        .map_err(|_| Error::ResourceUnavailable)?;
        let slot = NonNull::from(storage.as_mut());
        let owned = Owned {
            address: slot.as_ptr() as usize,
            _storage: storage,
        };
        super::thread::retain_operation(owner, owned)?;
        Ok(Self { owner, slot })
    }
}

impl<T> Deref for Scope<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the thread owns a stable allocation. Scope cannot be sent to
        // another thread. Its executing owner cannot be reclaimed: termination
        // waits for CPU handoff, and a retired execution never resumes.
        unsafe { &self.slot.as_ref().value }
    }
}

impl<T> DerefMut for Scope<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: Scope is the only payload borrower; the thread registry only
        // owns/drops the allocation and never accesses its contents.
        unsafe { &mut self.slot.as_mut().value }
    }
}

impl<T> Drop for Scope<T> {
    fn drop(&mut self) {
        // Destruction can enter IPC, VM or scheduler code. Detach under queue
        // exclusion, then destroy after releasing it.
        drop(super::thread::release_operation(
            self.owner,
            self.slot.as_ptr() as usize,
        ));
    }
}
