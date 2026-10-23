//! Non-reused identities for a native thread's image-scoped IPC lifetime.
//! Reserving is fallible; image replacement reserves before destructive work.
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);

/// Consumed exactly once when installing a newly reserved lifetime.
pub(crate) struct Reserved(u64);
impl Reserved {
    pub(crate) fn into_raw(self) -> u64 {
        self.0
    }
}

pub(crate) fn reserve() -> Option<Reserved> {
    NEXT.fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
        next.checked_add(1)
    })
    .ok()
    .map(Reserved)
}

/// A thread may exist without IPC resources after allocator exhaustion. Zero
/// is deliberately unusable by endpoint resolution, never a reused identity.
pub(super) fn initial() -> u64 {
    reserve().map_or(0, Reserved::into_raw)
}
