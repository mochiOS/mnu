//! Bounded owned bytes for consumers which verify content before interpreting
//! it. No paths, cursor mutation, allocation under object locks, or ELF policy.

use alloc::vec::Vec;

pub fn read(
    length: u64,
    maximum: usize,
    copy: impl FnOnce(&mut [u8]) -> Result<usize, u64>,
) -> Result<Vec<u8>, u64> {
    let length = usize::try_from(length)
        .ok()
        .filter(|length| *length <= maximum)
        .ok_or(mnu_abi::EFBIG)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| mnu_abi::ENOMEM)?;
    bytes.resize(length, 0);
    if copy(&mut bytes)? != length {
        return Err(mnu_abi::EIO);
    }
    Ok(bytes)
}
