use super::shared_pages::SizeError;
use core::ops::Range;

/// Checked geometry only: callers must serialize mapping revocation, boundary
/// zeroing and storage changes before publishing the new logical extent.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ResizePlan {
    pub(crate) length: u64,
    pub(crate) capacity: u64,
    pub(crate) invalidate: Option<Range<u64>>,
    pub(crate) zero: Option<Range<u64>>,
}

fn capacity(length: u64, page_bytes: u64, maximum_pages: u64) -> Result<u64, SizeError> {
    if !page_bytes.is_power_of_two() {
        return Err(SizeError::Invalid);
    }
    // Avoid length + page_bytes - 1 overflowing before division.
    let pages = (length / page_bytes)
        .checked_add(u64::from(length % page_bytes != 0))
        .ok_or(SizeError::LimitExceeded)?;
    if pages > maximum_pages {
        return Err(SizeError::LimitExceeded);
    }
    pages
        .checked_mul(page_bytes)
        .ok_or(SizeError::LimitExceeded)
}

pub(crate) fn plan(
    old_length: u64,
    length: u64,
    page_bytes: u64,
    maximum_pages: u64,
) -> Result<ResizePlan, SizeError> {
    let old_capacity = capacity(old_length, page_bytes, maximum_pages)?;
    let capacity = capacity(length, page_bytes, maximum_pages)?;
    let mut result = ResizePlan {
        length,
        capacity,
        invalidate: None,
        zero: None,
    };
    if length < old_length {
        // Revoke the boundary page too: a private copy may contain bytes beyond
        // the new extent, even when no complete storage page is removed.
        result.invalidate = Some((length / page_bytes * page_bytes)..old_capacity);
        if length < capacity {
            result.zero = Some(length..capacity);
        }
    } else if length > old_length && old_length < old_capacity {
        // Mapped padding may have been written. It must not become newly valid
        // contents on growth; pages beyond old_capacity are allocated zeroed.
        result.invalidate = Some((old_length / page_bytes * page_bytes)..old_capacity);
        result.zero = Some(old_length..old_capacity);
    }
    Ok(result)
}
