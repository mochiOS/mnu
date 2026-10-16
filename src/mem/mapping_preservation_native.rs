//! Extent-boundary pages keep their private bytes and original PTE flags.
//! Only their invalid suffix is zeroed, after backing commit and TLB ack.
use super::{
    mapping_revocation::{self, Backend},
    mapping_revocation_native::Native,
    paging,
};
use mnu_abi::status::Error;

pub(crate) struct PreservedPage {
    pub table: u64,
    pub address: u64,
    pub zero_from: usize,
}

impl PreservedPage {
    pub(crate) fn for_mapping(
        table: u64,
        start: u64,
        length: u64,
        offset: u64,
        boundary: u64,
    ) -> Result<Option<Self>, Error> {
        if boundary & 4095 == 0 {
            return Ok(None);
        }
        if table == 0
            || table & 4095 != 0
            || start & 4095 != 0
            || offset & 4095 != 0
            || length & 4095 != 0
        {
            return Err(Error::InvalidArgument);
        }
        let page = boundary & !4095;
        let end = page.checked_add(4096).ok_or(Error::InvalidArgument)?;
        let Some((address, high)) =
            mapping_revocation::virtual_overlap(start, length, offset, page, end)
                .map_err(|_| Error::InvalidArgument)?
        else {
            return Ok(None);
        };
        if high - address != 4096 {
            return Err(Error::InvalidArgument);
        }
        Ok(Some(Self {
            table,
            address,
            zero_from: (boundary & 4095) as usize,
        }))
    }
}

/// Only backends which retain owned RAM frames can preserve writable suffixes.
/// Exclusion and root lifetimes remain the backend's responsibility.
pub(crate) trait FrameBackend:
    Backend<Page = paging::SuspendedUserPage, Error = Error>
{
    fn owns_ram_frames(&self) -> bool;
}

impl FrameBackend for Native<'_> {
    fn owns_ram_frames(&self) -> bool {
        Native::owns_ram_frames(self)
    }
}

/// Keep either a borrowed or owned boundary plan alongside its backend. This
/// does not relax that backend's mapping-lock/exclusion requirements.
pub(crate) struct Preserving<B, P> {
    inner: B,
    preserved: P,
}

pub(crate) struct Page {
    original: paging::SuspendedUserPage,
    zero: Option<(u64, usize)>,
}

impl<B: FrameBackend, P: AsRef<[PreservedPage]>> Preserving<B, P> {
    pub(crate) fn new(inner: B, preserved: P) -> Result<Self, Error> {
        // Borrowed/MMIO mappings must never be treated as writable RAM.
        if !inner.owns_ram_frames() {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { inner, preserved })
    }

    /// Local publication can mutate the retained backing state without moving
    /// its exclusion lease out before the journal finishes its PTE work.
    pub(crate) fn inner_mut(&mut self) -> &mut B {
        &mut self.inner
    }
}

impl<B: FrameBackend, P: AsRef<[PreservedPage]>> Backend for Preserving<B, P> {
    type Page = Page;
    type Error = Error;

    fn next_page(&mut self, table: u64, start: u64, end: u64) -> Result<Option<u64>, Error> {
        self.inner.next_page(table, start, end)
    }
    fn suspend(&mut self, table: u64, address: u64) -> Result<Option<Page>, Error> {
        let mut matches = self
            .preserved
            .as_ref()
            .iter()
            .filter(|entry| entry.table == table && entry.address == address);
        let selected = matches.next();
        if matches.next().is_some() {
            return Err(Error::InvalidArgument);
        }
        let Some(original) = self.inner.suspend(table, address)? else {
            return Ok(None);
        };
        let zero = match selected {
            Some(entry) => match original.suffix_address(entry.zero_from) {
                Ok(range) => Some(range),
                Err(_) => {
                    self.inner.restore(original);
                    return Err(Error::InvalidAddress);
                }
            },
            None => None,
        };
        Ok(Some(Page { original, zero }))
    }
    fn restore(&mut self, page: Page) {
        self.inner.restore(page.original);
    }
    fn synchronize(&mut self) -> Result<(), Error> {
        self.inner.synchronize()
    }
    fn release(&mut self, page: Page) {
        if let Some((start, length)) = page.zero {
            // The transaction acknowledged every old translation and finished
            // its infallible backing commit. The original frame is still owned
            // by this suspended PTE, including a private COW frame.
            for offset in 0..length {
                unsafe { core::ptr::write_volatile((start + offset as u64) as *mut u8, 0) };
            }
            self.inner.restore(page.original);
        } else {
            self.inner.release(page.original);
        }
    }
}
