//! Read-only discovery skips absent page-table subtrees, not virtual pages.
#[derive(Clone, Copy)]
pub(crate) enum Entry {
    Absent,
    Branch(u64),
    Leaf,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error<E> {
    InvalidRange,
    InvalidTree,
    Backend(E),
}

/// The caller retains the root and excludes page-table writers throughout
/// discovery and any subsequent use of the returned address.
pub(crate) fn next<E>(
    root: u64,
    start: u64,
    end: u64,
    inspect: impl FnMut(u64, usize, u8) -> Result<Entry, E>,
) -> Result<Option<u64>, Error<E>> {
    find(root, start, end, false, inspect).map(|span| span.map(|(address, _)| address))
}

/// Placement can skip an entire occupied huge leaf. Revocation's `next`
/// deliberately continues to reject leaves larger than its 4KiB tokens.
pub(crate) fn next_span<E>(
    root: u64,
    start: u64,
    end: u64,
    inspect: impl FnMut(u64, usize, u8) -> Result<Entry, E>,
) -> Result<Option<(u64, u64)>, Error<E>> {
    find(root, start, end, true, inspect)
}

fn find<E>(
    root: u64,
    start: u64,
    end: u64,
    huge_leaves: bool,
    mut inspect: impl FnMut(u64, usize, u8) -> Result<Entry, E>,
) -> Result<Option<(u64, u64)>, Error<E>> {
    if root == 0
        || root & 4095 != 0
        || start & 4095 != 0
        || end & 4095 != 0
        || start > end
        || end > (1 << 47)
    {
        return Err(Error::InvalidRange);
    }
    let mut address = start;
    'search: while address < end {
        let mut table = root;
        for level in (1..=4).rev() {
            let shift = 12 + 9 * (level - 1);
            let index = ((address >> shift) & 511) as usize;
            match inspect(table, index, level).map_err(Error::Backend)? {
                Entry::Absent => {
                    address = ((address >> shift) + 1) << shift;
                    continue 'search;
                }
                Entry::Leaf if level == 1 || (huge_leaves && level < 4) => {
                    return Ok(Some((address, ((address >> shift) + 1) << shift)));
                }
                Entry::Branch(child) if level > 1 && child != 0 && child & 4095 == 0 => {
                    table = child;
                }
                _ => return Err(Error::InvalidTree),
            }
        }
    }
    Ok(None)
}
