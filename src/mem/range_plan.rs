use alloc::vec::Vec;
use mnu_abi::status::Error;

/// Snapshot a fully covered address range before performing external I/O.
/// The lookup supplies the containing region's end and optional owned work.
/// Regions without work still participate in coverage validation.
pub(crate) fn collect<T>(
    start: u64,
    length: u64,
    mut lookup: impl FnMut(u64) -> Option<(u64, Option<T>)>,
) -> Result<Vec<(T, u64)>, Error> {
    let end = start.checked_add(length).ok_or(Error::InvalidAddress)?;
    let mut cursor = start;
    let mut work = Vec::new();
    while cursor < end {
        let (region_end, item) = lookup(cursor).ok_or(Error::InvalidAddress)?;
        if region_end <= cursor {
            return Err(Error::BackingFailure);
        }
        let next = core::cmp::min(region_end, end);
        if let Some(item) = item {
            work.try_reserve(1)
                .map_err(|_| Error::ResourceUnavailable)?;
            work.push((item, next - cursor));
        }
        cursor = next;
    }
    Ok(work)
}
