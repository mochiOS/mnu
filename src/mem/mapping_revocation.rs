//! Transactional mapping suspension. Native VM code must hold its mapping
//! lock and exclude new backing population until the enclosing resize commits.
use alloc::vec::Vec;

pub(crate) trait Backend {
    type Page;
    type Error;
    /// Retain the mapping's frame ownership, removing hardware PRESENT only.
    /// Failure must leave this particular entry unchanged.
    fn suspend(&mut self, table: u64, address: u64) -> Result<Option<Self::Page>, Self::Error>;
    fn restore(&mut self, page: Self::Page);
    /// Must wait for every CPU capable of retaining old translations.
    fn synchronize(&mut self) -> Result<(), Self::Error>;
    /// Clear the suspended entry and release its retained mapping reference.
    /// Called only after successful synchronization while the VM lock is held.
    fn release(&mut self, page: Self::Page);
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error<E> {
    InvalidRange,
    Allocation,
    Backend(E),
}

/// Ranges are (page-table identity, virtual start, exclusive virtual end).
/// Plan and reserve storage BEFORE editing any page table. No allocation or
/// fallible edit remains in the post-synchronization release phase.
pub(crate) fn revoke<B: Backend>(
    ranges: impl IntoIterator<Item = (u64, u64, u64)>,
    backend: &mut B,
) -> Result<(), Error<B::Error>> {
    let mut plan = Vec::new();
    let mut count = 0usize;
    for (table, start, end) in ranges {
        if start >= end || table & 4095 != 0 || start & 4095 != 0 || end & 4095 != 0 {
            return Err(Error::InvalidRange);
        }
        let pages = usize::try_from((end - start) / 4096).map_err(|_| Error::InvalidRange)?;
        count = count.checked_add(pages).ok_or(Error::InvalidRange)?;
        plan.try_reserve(1).map_err(|_| Error::Allocation)?;
        plan.push((table, start, end));
    }
    // The same PTE must not be suspended/released twice. Distinct page tables
    // may use identical virtual ranges; overlapping ranges within one cannot.
    plan.sort_unstable();
    if plan
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0 && pair[1].1 < pair[0].2)
    {
        return Err(Error::InvalidRange);
    }
    let mut suspended = Vec::new();
    suspended
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    for (table, start, end) in plan {
        let mut address = start;
        while address < end {
            match backend.suspend(table, address) {
                Ok(Some(page)) => suspended.push(page),
                Ok(None) => {}
                Err(error) => {
                    for page in suspended.into_iter().rev() {
                        backend.restore(page);
                    }
                    return Err(Error::Backend(error));
                }
            }
            address += 4096;
        }
    }
    if suspended.is_empty() {
        return Ok(());
    }
    if let Err(error) = backend.synchronize() {
        for page in suspended.into_iter().rev() {
            backend.restore(page);
        }
        return Err(Error::Backend(error));
    }
    for page in suspended {
        backend.release(page);
    }
    Ok(())
}

/// Select the virtual overlap of a backing-object range, checking all additions
/// before touching mappings. Selection is independent of service names/paths.
pub(crate) fn virtual_overlap(
    virtual_start: u64,
    length: u64,
    backing_offset: u64,
    start: u64,
    end: u64,
) -> Result<Option<(u64, u64)>, ()> {
    if start > end {
        return Err(());
    }
    let mapping_end = backing_offset.checked_add(length).ok_or(())?;
    virtual_start.checked_add(length).ok_or(())?;
    let low = backing_offset.max(start);
    let high = mapping_end.min(end);
    if low >= high {
        return Ok(None);
    }
    Ok(Some((
        virtual_start + (low - backing_offset),
        virtual_start + (high - backing_offset),
    )))
}
