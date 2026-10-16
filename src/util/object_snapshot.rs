//! Bounded owned bytes for consumers which verify content before interpreting
//! it. No paths, cursor mutation, allocation under object locks, or ELF policy.

use alloc::vec::Vec;

/// Allocate initialized storage without invoking the allocation-error handler.
/// Callers validate their own extent and policy bounds before requesting it.
pub fn zeroed_native(length: usize) -> Result<Vec<u8>, mnu_abi::status::Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| mnu_abi::status::Error::ResourceUnavailable)?;
    bytes.resize(length, 0);
    Ok(bytes)
}

pub fn read(
    length: u64,
    maximum: usize,
    copy: impl FnOnce(&mut [u8]) -> Result<usize, u64>,
) -> Result<Vec<u8>, u64> {
    let length = usize::try_from(length)
        .ok()
        .filter(|length| *length <= maximum)
        .ok_or(mnu_abi::status::Error::LimitExceeded.into_raw())?;
    let mut bytes = zeroed_native(length).map_err(mnu_abi::status::Error::into_raw)?;
    if copy(&mut bytes)? != length {
        return Err(mnu_abi::status::Error::BackingFailure.into_raw());
    }
    Ok(bytes)
}
