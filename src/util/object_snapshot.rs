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

/// Snapshot a bounded positional source without requiring cursor or metadata
/// authority. Short reads are progress, not EOF. At the exact bound, probe one
/// byte to distinguish an exact-size object from a truncated snapshot.
pub fn read_to_end(
    maximum: usize,
    chunk: usize,
    mut copy: impl FnMut(u64, &mut [u8]) -> Result<usize, u64>,
) -> Result<Vec<u8>, u64> {
    use mnu_abi::status::Error;
    if chunk == 0 {
        return Err(Error::InvalidArgument.into_raw());
    }
    let mut bytes = Vec::new();
    loop {
        let start = bytes.len();
        let offset = u64::try_from(start).map_err(|_| Error::LimitExceeded.into_raw())?;
        if start == maximum {
            let mut probe = [0];
            return match copy(offset, &mut probe)? {
                0 => Ok(bytes),
                1 => Err(Error::LimitExceeded.into_raw()),
                _ => Err(Error::BackingFailure.into_raw()),
            };
        }
        let count = chunk.min(maximum - start);
        if bytes.capacity() - start < count {
            let capacity = bytes.capacity().max(chunk).saturating_mul(2).min(maximum);
            bytes
                .try_reserve_exact(capacity - start)
                .map_err(|_| Error::ResourceUnavailable.into_raw())?;
        }
        bytes.resize(start + count, 0);
        let copied = copy(offset, &mut bytes[start..])?;
        if copied > count {
            return Err(Error::BackingFailure.into_raw());
        }
        bytes.truncate(start + copied);
        if copied == 0 {
            return Ok(bytes);
        }
    }
}
