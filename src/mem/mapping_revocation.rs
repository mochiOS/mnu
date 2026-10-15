//! Transactional mapping suspension. Native VM code must hold its mapping
//! lock and exclude new backing population until the enclosing resize commits.
use alloc::vec::Vec;

pub(crate) trait Backend {
    type Page;
    type Error;
    /// Discover an allocated user leaf without editing it. Skip absent
    /// subtrees; include non-present leaves that still own frame references.
    fn next_page(&mut self, table: u64, start: u64, end: u64) -> Result<Option<u64>, Self::Error>;
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
    revoke_with(ranges, backend, || Ok(()))
}

/// Run a backing/cache commit after every selected translation is suspended
/// and remote CPUs have acknowledged invalidation, but before releasing any
/// retained frame. An unsuccessful commit must leave backing unchanged; its
/// error restores all original mappings and is returned as `Error::Backend`.
///
/// The caller must keep the mapping/population exclusion held throughout.
/// `commit` must not wait for IPC, reenter VM mapping operations or access the
/// suspended virtual addresses. Prepare allocations and external I/O before
/// entering this transaction; this callback only publishes local state.
pub(crate) fn revoke_with<B: Backend, T>(
    ranges: impl IntoIterator<Item = (u64, u64, u64)>,
    backend: &mut B,
    commit: impl FnOnce() -> Result<T, B::Error>,
) -> Result<T, Error<B::Error>> {
    let mut plan = Vec::new();
    for (table, start, end) in ranges {
        if start >= end || table & 4095 != 0 || start & 4095 != 0 || end & 4095 != 0 {
            return Err(Error::InvalidRange);
        }
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
    // Discover first: allocation and walk errors must leave every PTE intact.
    // Storage scales with allocated leaves, not the virtual reservation size.
    let mut pages = Vec::new();
    for (table, start, end) in plan {
        let mut cursor = start;
        while cursor < end {
            let Some(address) = backend
                .next_page(table, cursor, end)
                .map_err(Error::Backend)?
            else {
                break;
            };
            if address < cursor || address >= end || address & 4095 != 0 {
                return Err(Error::InvalidRange);
            }
            pages.try_reserve(1).map_err(|_| Error::Allocation)?;
            pages.push((table, address));
            cursor = address + 4096;
        }
    }
    let mut suspended = Vec::new();
    suspended
        .try_reserve_exact(pages.len())
        .map_err(|_| Error::Allocation)?;
    for (table, address) in pages {
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
    }
    if !suspended.is_empty() {
        if let Err(error) = backend.synchronize() {
            for page in suspended.into_iter().rev() {
                backend.restore(page);
            }
            return Err(Error::Backend(error));
        }
    }
    let result = match commit() {
        Ok(result) => result,
        Err(error) => {
            for page in suspended.into_iter().rev() {
                backend.restore(page);
            }
            return Err(Error::Backend(error));
        }
    };
    for page in suspended {
        backend.release(page);
    }
    Ok(result)
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
