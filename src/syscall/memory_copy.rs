//! Own-address-space byte copying without entering a userspace exception path.

use mnu_abi::status::Error;

pub fn copy(destination: u64, source: u64, length: u64) -> u64 {
    let Ok(length) = usize::try_from(length) else {
        return Error::LimitExceeded.into_raw();
    };
    if length > mnu_abi::memory_copy::MAX_BYTES {
        return Error::LimitExceeded.into_raw();
    }
    if length == 0 {
        return 0;
    }
    // A snapshot gives one bounded operation overlap-safe semantics. Existing
    // usercopy faults in backing, handles COW, and revalidates the current root
    // and leaf permissions under the process lock for each resident copy.
    let mut snapshot = [0u8; mnu_abi::memory_copy::MAX_BYTES];
    let snapshot = &mut snapshot[..length];
    if let Err(error) = super::copy_from_user_native(source, snapshot) {
        return error.into_raw();
    }
    if let Err(error) = super::copy_to_user_native(destination, snapshot) {
        return error.into_raw();
    }
    length as u64
}
