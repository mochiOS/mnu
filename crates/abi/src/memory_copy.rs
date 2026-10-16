//! Bounded snapshots between addresses already owned by the calling process.
//!
//! Unavailable or inaccessible addresses return `status::Error::InvalidAddress`
//! without delivering a userspace exception. Allocation and backing failures
//! retain the distinct `ResourceUnavailable` and `BackingFailure` categories.
//! A destination failure may leave an already-copied prefix modified.

/// A fixed operation bound keeps kernel scratch storage and copy work finite.
/// Larger transfers are explicitly split by the caller; they are not atomic.
/// Exceeding this bound returns [`crate::status::Error::LimitExceeded`] before
/// either address is accessed.
pub const MAX_BYTES: usize = 4096;
