use alloc::vec::Vec;

/// Snapshot a fully covered address range before performing external I/O.
/// The lookup supplies the containing region's end and optional owned work.
/// Regions without work still participate in coverage validation.
pub(crate) fn collect<T>(
    start: u64,
    length: u64,
    mut lookup: impl FnMut(u64) -> Option<(u64, Option<T>)>,
) -> Option<Vec<(T, u64)>> {
    let end = start.checked_add(length)?;
    let mut cursor = start;
    let mut work = Vec::new();
    while cursor < end {
        let (region_end, item) = lookup(cursor)?;
        if region_end <= cursor {
            return None;
        }
        let next = core::cmp::min(region_end, end);
        if let Some(item) = item {
            work.push((item, next - cursor));
        }
        cursor = next;
    }
    Some(work)
}
