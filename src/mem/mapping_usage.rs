//! Union of disjoint VM reservations and retained user page-table leaves.
//! Allocation-free; the caller excludes metadata and page-table writers.

const PAGE: u64 = 4096;
const USER_END: u64 = 1 << 47;
use super::scan_budget::Budget;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error<E> {
    InvalidRange,
    WorkLimit,
    Backend(E),
}

pub(crate) fn bytes<E, I>(
    regions: I,
    mut next_leaf: impl FnMut(u64, u64) -> Result<Option<u64>, E>,
) -> Result<u64, Error<E>>
where
    I: Iterator<Item = (u64, u64)> + Clone,
{
    bytes_bounded(regions, &mut Budget::new(), |start, end, _| {
        next_leaf(start, end)
    })
}

pub(crate) fn bytes_bounded<E, I>(
    regions: I,
    budget: &mut Budget,
    mut next_leaf: impl FnMut(u64, u64, &mut Budget) -> Result<Option<u64>, E>,
) -> Result<u64, Error<E>>
where
    I: Iterator<Item = (u64, u64)> + Clone,
{
    let mut total = 0u64;
    for (index, (start, end)) in regions.clone().enumerate() {
        if !budget.take(1) {
            return Err(Error::WorkLimit);
        }
        if start >= end || start & (PAGE - 1) != 0 || end & (PAGE - 1) != 0 || end > USER_END {
            return Err(Error::InvalidRange);
        }
        for (other_start, other_end) in regions.clone().take(index) {
            if !budget.take(1) {
                return Err(Error::WorkLimit);
            }
            if start < other_end && other_start < end {
                return Err(Error::InvalidRange);
            }
        }
        total = total.checked_add(end - start).ok_or(Error::InvalidRange)?;
    }
    let mut cursor = 0;
    loop {
        if !budget.take(1) {
            return Err(Error::WorkLimit);
        }
        let Some(page) = next_leaf(cursor, USER_END, budget).map_err(Error::Backend)? else {
            break;
        };
        if page < cursor || page >= USER_END || page & (PAGE - 1) != 0 {
            return Err(Error::InvalidRange);
        }
        let mut covered_end = None;
        for (start, end) in regions.clone() {
            if !budget.take(1) {
                return Err(Error::WorkLimit);
            }
            if start <= page && page < end {
                covered_end = Some(end);
                break;
            }
        }
        if let Some(end) = covered_end {
            // A faulted 1TiB reservation still takes one jump, not a walk of
            // every populated page. These pages were already counted above.
            cursor = end;
        } else {
            total = total.checked_add(PAGE).ok_or(Error::InvalidRange)?;
            cursor = page + PAGE;
        }
    }
    Ok(total)
}

/// Only growth is being proposed here; this operation never replaces a live
/// mapping. Validate the native mapping arguments and authority separately.
pub(crate) fn permits(used: u64, additional: u64, ceiling: u64) -> bool {
    used.checked_add(additional)
        .is_some_and(|total| total <= ceiling)
}
