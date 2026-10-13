use alloc::collections::BTreeMap;
use alloc::sync::Arc;

/// Resource-owned pages, independent of any process's virtual addresses.
/// Access must be serialized by the enclosing memory object's lock. Retained
/// page references keep storage alive after the object or a handle is dropped.
pub(crate) struct SharedPages<Page> {
    length: u64,
    page_bytes: u64,
    maximum_pages: u64,
    pages: BTreeMap<u64, Arc<Page>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SizeError {
    Invalid,
    LimitExceeded,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PageError<Error> {
    OutOfBounds,
    Allocation(Error),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ResizeError<Error> {
    Size(SizeError),
    Preparation(Error),
    Revocation(Error),
}

impl<Page> SharedPages<Page> {
    /// Byte-sized logical extent with page-rounded, lazily populated storage.
    /// The original allocation ceiling remains attached to the object.
    pub(crate) fn new_bytes(
        length: u64,
        page_bytes: u64,
        maximum_pages: u64,
    ) -> Result<Self, SizeError> {
        super::byte_extent::plan(0, length, page_bytes, maximum_pages)?;
        Ok(Self {
            length,
            page_bytes,
            maximum_pages,
            pages: BTreeMap::new(),
        })
    }

    /// Fixed native objects are page-granular. The creator's page limit is checked
    /// before any storage allocation; no unchecked size rounding is performed.
    pub(crate) fn new(length: u64, page_bytes: u64, maximum_pages: u64) -> Result<Self, SizeError> {
        if length == 0 {
            return Err(SizeError::Invalid);
        }
        Self::new_resizable(length, page_bytes, maximum_pages)
    }

    /// Empty backing is valid for a resizable object. Keep the existing fixed
    /// object constructor's nonempty contract. Byte extents use `new_bytes`.
    pub(crate) fn new_resizable(
        length: u64,
        page_bytes: u64,
        maximum_pages: u64,
    ) -> Result<Self, SizeError> {
        if !page_bytes.is_power_of_two() || length % page_bytes != 0 {
            return Err(SizeError::Invalid);
        }
        if length / page_bytes > maximum_pages {
            return Err(SizeError::LimitExceeded);
        }
        Ok(Self {
            length,
            page_bytes,
            maximum_pages,
            pages: BTreeMap::new(),
        })
    }

    pub(crate) fn length(&self) -> u64 {
        self.length
    }

    pub(crate) fn contains_range(&self, offset: u64, length: u64) -> bool {
        offset
            .checked_add(length)
            .is_some_and(|end| end <= self.length)
    }

    /// The enclosing object lock serializes this with faults/population.
    /// Before a shrink can detach storage, the VM coordinator must revoke all
    /// mappings of [new_length, old_length), including remote TLB translations.
    /// A failed revocation leaves backing ownership and length unchanged.
    /// Existing aliases to retained pages are never replaced during growth.
    pub(crate) fn resize_with<Error>(
        &mut self,
        length: u64,
        revoke: impl FnOnce(u64, u64) -> Result<(), Error>,
    ) -> Result<(), ResizeError<Error>> {
        if length % self.page_bytes != 0 || self.length % self.page_bytes != 0 {
            return Err(ResizeError::Size(SizeError::Invalid));
        }
        self.resize_bytes_with(length, |_, _| Ok(()), revoke, |_, _| {})
    }

    /// Prepare fallible boundary access without modifying contents, then revoke
    /// aliases before an infallible zeroing commit. The enclosing object lock
    /// must exclude faults, I/O and resize throughout all three callbacks.
    pub(crate) fn resize_bytes_with<Token, Error>(
        &mut self,
        length: u64,
        prepare: impl FnOnce(&Page, core::ops::Range<u64>) -> Result<Token, Error>,
        revoke: impl FnOnce(u64, u64) -> Result<(), Error>,
        zero: impl FnOnce(&Page, Token),
    ) -> Result<(), ResizeError<Error>> {
        let plan =
            super::byte_extent::plan(self.length, length, self.page_bytes, self.maximum_pages)
                .map_err(ResizeError::Size)?;
        let boundary = match plan.zero {
            Some(range) => {
                let index = range.start / self.page_bytes;
                match self.pages.get(&index) {
                    Some(page) => {
                        let base = index * self.page_bytes;
                        let token = prepare(page, (range.start - base)..(range.end - base))
                            .map_err(ResizeError::Preparation)?;
                        Some((page.clone(), token))
                    }
                    // Absent pages are populated zeroed; no allocation needed.
                    None => None,
                }
            }
            None => None,
        };
        if let Some(range) = plan.invalidate {
            revoke(range.start, range.end).map_err(ResizeError::Revocation)?;
        }
        if let Some((page, token)) = boundary {
            zero(&page, token);
        }
        if length < self.length {
            let first_removed = plan.capacity / self.page_bytes;
            // Do not allocate a second tree after revocation has committed.
            // Removing this ledger's Arc never frees storage still pinned by
            // a prepared page or another retained owner.
            while self
                .pages
                .last_key_value()
                .is_some_and(|(&index, _)| index >= first_removed)
            {
                drop(self.pages.pop_last());
            }
        }
        self.length = plan.length;
        Ok(())
    }

    /// The allocator must return a newly zeroed, owned page. Allocation failure
    /// leaves the page absent, so another fault can retry rather than observing
    /// partially initialized or recycled physical storage.
    pub(crate) fn page_or_try_insert<Error>(
        &mut self,
        index: u64,
        allocate: impl FnOnce() -> Result<Page, Error>,
    ) -> Result<Arc<Page>, PageError<Error>> {
        let count = self.length / self.page_bytes + u64::from(self.length % self.page_bytes != 0);
        if index >= count {
            return Err(PageError::OutOfBounds);
        }
        if let Some(page) = self.pages.get(&index) {
            return Ok(page.clone());
        }
        let page = Arc::new(allocate().map_err(PageError::Allocation)?);
        self.pages.insert(index, page.clone());
        Ok(page)
    }
}
