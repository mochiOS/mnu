//! Owned syscall input, prepared before any destructive image transition.
use alloc::string::String;
use alloc::vec::Vec;

/// Prepare text before creating or committing image state. Replacements whose
/// authorization already owns this text move that ownership instead.
pub(super) fn text(value: &str) -> Result<String, mnu_abi::status::Error> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| mnu_abi::status::Error::ResourceUnavailable)?;
    owned.push_str(value);
    Ok(owned)
}

pub(super) fn from_user_native(
    pointer: u64,
    length: usize,
) -> Result<Vec<u8>, mnu_abi::status::Error> {
    let mut bytes = crate::util::object_snapshot::zeroed_native(length)?;
    crate::syscall::copy_from_user_native(pointer, &mut bytes)?;
    Ok(bytes)
}
