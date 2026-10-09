use alloc::collections::BTreeMap;
use alloc::sync::Arc;

/// Resource-owned pages, independent of any process's virtual addresses.
/// Access must be serialized by the enclosing memory object's lock. Retained
/// page references keep storage alive after the object or a handle is dropped.
pub(crate) struct SharedPages<Page> {
    length: u64,
    page_bytes: u64,
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

impl<Page> SharedPages<Page> {
    /// Native objects are page-granular. The creator's page limit is checked
    /// before any storage allocation; no unchecked size rounding is performed.
    pub(crate) fn new(length: u64, page_bytes: u64, maximum_pages: u64) -> Result<Self, SizeError> {
        if length == 0 || !page_bytes.is_power_of_two() || length % page_bytes != 0 {
            return Err(SizeError::Invalid);
        }
        if length / page_bytes > maximum_pages {
            return Err(SizeError::LimitExceeded);
        }
        Ok(Self {
            length,
            page_bytes,
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

    /// The allocator must return a newly zeroed, owned page. Allocation failure
    /// leaves the page absent, so another fault can retry rather than observing
    /// partially initialized or recycled physical storage.
    pub(crate) fn page_or_try_insert<Error>(
        &mut self,
        index: u64,
        allocate: impl FnOnce() -> Result<Page, Error>,
    ) -> Result<Arc<Page>, PageError<Error>> {
        if index >= self.length / self.page_bytes {
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
