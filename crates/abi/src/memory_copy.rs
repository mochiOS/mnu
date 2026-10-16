//! Bounded snapshots between addresses already owned by the calling process.

/// A fixed operation bound keeps kernel scratch storage and copy work finite.
/// Larger transfers are explicitly split by the caller; they are not atomic.
pub const MAX_BYTES: usize = 4096;
