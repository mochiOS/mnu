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
