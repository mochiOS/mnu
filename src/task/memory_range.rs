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
