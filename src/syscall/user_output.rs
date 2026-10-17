//! Fault preparation precedes resource locking. A bounded resident writer is
//! usable only during the callback, while the original process root is held.
use mnu_abi::status::Error;

pub(crate) fn with_user_output_native<T>(
    address: u64,
    maximum: usize,
    operation: impl FnOnce(&mut dyn FnMut(&[u8]) -> Result<(), Error>) -> Result<T, Error>,
) -> Result<T, Error> {
    if maximum == 0 {
        return Err(Error::InvalidArgument);
    }
    let table = super::current_user_page_table().ok_or(Error::InvalidAddress)?;
    let end = address
        .checked_add(maximum as u64)
        .ok_or(Error::InvalidAddress)?;
    // This may resolve COW or call a provider. No resource lock is held yet.
    super::fault_in_user_range(table, address, maximum as u64, true)?;
    let pid = super::security::current_process_id().ok_or(Error::InvalidAddress)?;
    crate::task::with_process_mut(pid, |process| {
        if process.page_table() != Some(table) {
            return Err(Error::InvalidAddress);
        }
        crate::mem::mapping_admission::check_native(process.memory_regions(), address, end)?;
        // A concurrent unmap, refresh or protection change may have won after
        // fault preparation. Never invoke the resource callback in that case.
        if !crate::mem::paging::is_user_range_writable_in_table(table, address, maximum as u64) {
            return Err(Error::NotReady);
        }
        let mut copy = |bytes: &[u8]| {
            if bytes.len() > maximum {
                return Err(Error::InvalidArgument);
            }
            // All pages are writable, so this path cannot enter COW/provider
            // preparation. Mapping exclusion is retained through the callback.
            crate::mem::paging::copy_to_user_in_table(table, address, bytes)
                .map_err(super::usercopy_error::resident)
        };
        operation(&mut copy)
    })
    .unwrap_or(Err(Error::InvalidAddress))
}
