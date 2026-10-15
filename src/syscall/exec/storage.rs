//! Owned syscall input, prepared before any destructive image transition.
use alloc::vec::Vec;

pub(super) fn from_user(pointer: u64, length: usize) -> Result<Vec<u8>, u64> {
    let mut bytes = crate::util::object_snapshot::zeroed(length)?;
    crate::syscall::copy_from_user(pointer, &mut bytes)?;
    Ok(bytes)
}
