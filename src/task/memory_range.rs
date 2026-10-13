//! Checked interval arithmetic for native VM region removal.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Range {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Cut {
    pub before: Option<Range>,
    pub removed: Option<Range>,
    pub after: Option<Range>,
}

pub(crate) fn cut(region: Range, removal: Range) -> Option<Cut> {
    if region.start >= region.end || removal.start >= removal.end {
        return None;
    }
    let start = region.start.max(removal.start);
    let end = region.end.min(removal.end);
    if start >= end {
        return Some(Cut {
            before: Some(region),
            removed: None,
            after: None,
        });
    }
    Some(Cut {
        before: (region.start < start).then_some(Range {
            start: region.start,
            end: start,
        }),
        removed: Some(Range { start, end }),
        after: (end < region.end).then_some(Range {
            start: end,
            end: region.end,
        }),
    })
}

/// Tests every intersecting page, not whether the whole interval is resident.
pub(crate) fn any_page(
    start: u64,
    len: u64,
    mut occupied: impl FnMut(u64) -> bool,
) -> Option<bool> {
    if len == 0 {
        return Some(false);
    }
    let last = start.checked_add(len - 1)? & !4095;
    let mut page = start & !4095;
    loop {
        if occupied(page) {
            return Some(true);
        }
        if page == last {
            return Some(false);
        }
        page = page.checked_add(4096)?;
    }
}

/// Validate reserved-or-resident coverage without inspecting every page in a
/// reservation. A region end is usable only for complete pages; gaps still
/// require individually retained leaves (for example an ELF image or stack).
pub(crate) fn covers_pages(
    start: u64,
    end: u64,
    mut region_end: impl FnMut(u64) -> Option<u64>,
    mut retained: impl FnMut(u64) -> bool,
) -> bool {
    if start > end || start & 4095 != 0 || end & 4095 != 0 {
        return false;
    }
    let mut page = start;
    while page < end {
        let next = page + 4096;
        if let Some(limit) = region_end(page).filter(|&limit| limit >= next) {
            page = (limit & !4095).min(end);
        } else if retained(page) {
            page = next;
        } else {
            return false;
        }
    }
    true
}
