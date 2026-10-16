//! Native mechanism failures, independent of any userspace errno namespace.
//!
//! This reserved tag survives sign-extension through a signed 32-bit service
//! status field. Unknown codes in the domain are failures, never success data.
//! Compatibility layers choose their own error mapping at their API boundary.

const TAG: u64 = 0xffff_ffff_fffc_0000;
const MASK: u64 = 0xffff_ffff_ffff_0000;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The requested work exceeds a mechanism's explicitly published bound.
    LimitExceeded = 1,
    /// The caller's address range is absent or lacks the requested access.
    InvalidAddress = 2,
    /// Storage needed to complete the mechanism could not be allocated.
    ResourceUnavailable = 3,
    /// A backing object failed while resolving the requested operation.
    BackingFailure = 4,
}

impl Error {
    pub const fn into_raw(self) -> u64 {
        TAG | self as u64
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if !is_error(raw) {
            return None;
        }
        match raw & !MASK {
            1 => Some(Self::LimitExceeded),
            2 => Some(Self::InvalidAddress),
            3 => Some(Self::ResourceUnavailable),
            4 => Some(Self::BackingFailure),
            _ => None,
        }
    }
}

pub const fn is_error(raw: u64) -> bool {
    raw & MASK == TAG
}
