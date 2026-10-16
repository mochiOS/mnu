//! Preserve mechanism failure categories without assigning userspace errno.
use mnu_abi::{MemoryFaultCause, status::Error};

pub(super) fn resident(error: crate::Kernel) -> Error {
    match error {
        crate::Kernel::Memory(crate::result::Memory::OutOfMemory) => Error::ResourceUnavailable,
        crate::Kernel::Memory(_) => Error::InvalidAddress,
        _ => Error::BackingFailure,
    }
}

pub(super) fn fault(cause: MemoryFaultCause) -> Error {
    match cause {
        MemoryFaultCause::ResourceUnavailable => Error::ResourceUnavailable,
        MemoryFaultCause::BackingFailure => Error::BackingFailure,
        MemoryFaultCause::Unmapped
        | MemoryFaultCause::AccessDenied
        | MemoryFaultCause::OutsideBacking
        | MemoryFaultCause::Unresolved => Error::InvalidAddress,
    }
}
