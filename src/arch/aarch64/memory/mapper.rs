//! Adapter from shared VM page operations to the native AArch64 mapper.
use super::{
    page_table::PageTableEntry, FrameAllocator, Page, PageSize, PageTable, PageTableFlags as Flags,
    PhysAddr, PhysFrame, Size4KiB, VirtAddr,
};
use crate::arch::selected::paging as native;

#[derive(Debug)]
pub enum MapToError<S: PageSize> {
    FrameAllocationFailed,
    FrameReleaseFailed,
    PageAlreadyMapped(PhysFrame<S>),
    ParentEntryHugePage,
    InvalidFrameAddress(PhysAddr),
    InvalidPermissions,
    UnsupportedConfiguration,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslateError {
    PageNotMapped,
    ParentEntryHugePage,
    InvalidFrameAddress(PhysAddr),
}
#[derive(Debug)]
pub enum UnmapError {
    PageNotMapped,
    ParentEntryHugePage,
}

#[must_use]
pub struct MapperFlush<S: PageSize> {
    page: Page<S>,
}
impl<S: PageSize> MapperFlush<S> {
    /// Consume a deferred-flush token. The ARM backend conservatively completes
    /// invalidation even when shared VM code knows its root is inactive: a root
    /// can still have cached translations from an earlier ASID assignment.
    pub fn ignore(self) {
        self.flush();
    }
    pub fn flush(self) {
        // SAFETY: VM mapping operations run at EL1 with roots retained under
        // writer exclusion. The broadcast includes global and ASID entries.
        unsafe { native::invalidate_page(self.page.start_address().as_u64()) };
    }
}

pub trait Mapper<S: PageSize> {
    unsafe fn map_to<A: FrameAllocator<S>>(
        &mut self,
        page: Page<S>,
        frame: PhysFrame<S>,
        flags: Flags,
        allocator: &mut A,
    ) -> Result<MapperFlush<S>, MapToError<S>>;
    unsafe fn map_to_with_table_flags<A: FrameAllocator<S>>(
        &mut self,
        page: Page<S>,
        frame: PhysFrame<S>,
        flags: Flags,
        parent_flags: Flags,
        allocator: &mut A,
    ) -> Result<MapperFlush<S>, MapToError<S>>;
    fn translate_page(&self, page: Page<S>) -> Result<PhysFrame<S>, TranslateError>;
    fn unmap(&mut self, page: Page<S>) -> Result<(PhysFrame<S>, MapperFlush<S>), UnmapError>;
    unsafe fn update_flags(
        &mut self,
        page: Page<S>,
        flags: Flags,
    ) -> Result<MapperFlush<S>, TranslateError>;
}
pub trait Translate {
    fn translate_addr(&self, address: VirtAddr) -> Option<PhysAddr>;
}

pub struct OffsetPageTable<'a> {
    root: &'a mut PageTable,
    offset: VirtAddr,
}

impl<'a> OffsetPageTable<'a> {
    /// # Safety
    /// Root and walk frames must stay pinned and exclusively editable for this
    /// lifetime. Every physical table must be accessible through the supplied
    /// linear offset. The VM retains backing ownership and writer exclusion.
    pub unsafe fn new(root: &'a mut PageTable, offset: VirtAddr) -> Self {
        Self { root, offset }
    }
    fn physical_root(&self) -> u64 {
        self.root as *const PageTable as u64 - self.offset.as_u64()
    }
    unsafe fn table(&self, physical: PhysAddr) -> &PageTable {
        unsafe { &*((physical.as_u64() + self.offset.as_u64()) as *const PageTable) }
    }
    fn index(address: VirtAddr, level: usize) -> usize {
        ((address.as_u64() >> (39 - 9 * level)) & 511) as usize
    }
    /// Inspect vacancy without treating a suspended/reserved descriptor as
    /// free. The constructor's table lifetime and writer exclusion still apply.
    pub(crate) fn page_is_vacant(&self, page: Page) -> bool {
        let mut table = self.root as *const PageTable;
        for level in 0..4 {
            let entry = &unsafe { &*table }[Self::index(page.start_address(), level)];
            if entry.is_unused() {
                return true;
            }
            let flags = entry.flags();
            if level == 3 || !flags.contains(Flags::PRESENT) || flags.contains(Flags::HUGE_PAGE) {
                return false;
            }
            table = unsafe { self.table(entry.addr()) } as *const PageTable;
        }
        false
    }
    fn leaf(&self, page: Page) -> Result<*mut PageTableEntry, TranslateError> {
        let mut table = self.root as *const PageTable;
        for level in 0..3 {
            let entry = &unsafe { &*table }[Self::index(page.start_address(), level)];
            let flags = entry.flags();
            if !flags.contains(Flags::PRESENT) {
                return Err(TranslateError::PageNotMapped);
            }
            if flags.contains(Flags::HUGE_PAGE) {
                return Err(TranslateError::ParentEntryHugePage);
            }
            table = unsafe { self.table(entry.addr()) } as *const PageTable;
        }
        let index = Self::index(page.start_address(), 3);
        // SAFETY: The unsafe constructor binds all tables to the retained root
        // and VM exclusion. Mutating this pointer additionally requires &mut self.
        Ok(unsafe { PageTable::raw_entry(table.cast_mut(), index) }.cast())
    }
}

struct Tables<'a, A> {
    allocator: &'a mut A,
    offset: u64,
    release_failed: bool,
}

// SAFETY: FrameAllocator owns each frame and the OffsetPageTable constructor
// guarantees the linear table mapping. Unpublished allocation rollback returns
// frames through that same allocator; a failed return is reported explicitly.
unsafe impl<A: FrameAllocator<Size4KiB>> native::TableMemory for Tables<'_, A> {
    fn allocate_table(&mut self) -> Result<u64, native::Error> {
        let frame = self
            .allocator
            .allocate_frame()
            .ok_or(native::Error::OutOfMemory)?;
        let physical = frame.start_address().as_u64();
        let Some(address) = physical.checked_add(self.offset) else {
            self.release_failed |= !unsafe { self.allocator.deallocate_frame(frame) };
            return Err(native::Error::InvalidAddress);
        };
        // SAFETY: A fresh frame has no published mappings or walker references.
        unsafe { (&mut *(address as *mut PageTable)).clear() };
        Ok(physical)
    }
    unsafe fn free_table(&mut self, physical: u64) {
        let frame = PhysFrame::containing_address(PhysAddr::new(physical));
        self.release_failed |= !unsafe { self.allocator.deallocate_frame(frame) };
    }
    unsafe fn table_ptr(&self, physical: u64) -> *mut native::PageTable {
        (physical + self.offset) as *mut native::PageTable
    }
}

impl Mapper<Size4KiB> for OffsetPageTable<'_> {
    unsafe fn map_to<A: FrameAllocator<Size4KiB>>(
        &mut self,
        page: Page,
        frame: PhysFrame,
        flags: Flags,
        allocator: &mut A,
    ) -> Result<MapperFlush<Size4KiB>, MapToError<Size4KiB>> {
        let parent = Flags::PRESENT
            | Flags::WRITABLE
            | if flags.contains(Flags::USER_ACCESSIBLE) {
                Flags::USER_ACCESSIBLE
            } else {
                Flags::empty()
            };
        unsafe { self.map_to_with_table_flags(page, frame, flags, parent, allocator) }
    }
    unsafe fn map_to_with_table_flags<A: FrameAllocator<Size4KiB>>(
        &mut self,
        page: Page,
        frame: PhysFrame,
        flags: Flags,
        parent: Flags,
        allocator: &mut A,
    ) -> Result<MapperFlush<Size4KiB>, MapToError<Size4KiB>> {
        let writable = flags.contains(Flags::WRITABLE);
        let executable = flags.contains(Flags::PRESENT) && !flags.contains(Flags::NO_EXECUTE);
        let device = flags.contains(Flags::NO_CACHE | Flags::WRITE_THROUGH);
        if flags.contains(Flags::HUGE_PAGE) || executable && (writable || device) {
            return Err(MapToError::InvalidPermissions);
        }
        let config = native::Config::detect().map_err(|_| MapToError::UnsupportedConfiguration)?;
        let root = self.physical_root();
        let mut tables = Tables {
            allocator,
            offset: self.offset.as_u64(),
            release_failed: false,
        };
        let access = native::Access {
            user: flags.contains(Flags::USER_ACCESSIBLE),
            writable,
            executable,
            memory: if device {
                native::MemoryType::Device
            } else {
                native::MemoryType::Normal
            },
        };
        let result =
            unsafe { native::Mapper::new(root, config, &mut tables) }.and_then(|mut mapper| {
                mapper.map(
                    page.start_address().as_u64(),
                    frame.start_address().as_u64(),
                    access,
                )
            });
        if tables.release_failed {
            return Err(MapToError::FrameReleaseFailed);
        }
        if let Err(error) = result {
            return Err(match error {
                native::Error::OutOfMemory => MapToError::FrameAllocationFailed,
                native::Error::AlreadyMapped => {
                    let entry = self
                        .leaf(page)
                        .map_err(|_| MapToError::ParentEntryHugePage)?;
                    MapToError::PageAlreadyMapped(PhysFrame::containing_address(
                        unsafe { &*entry }.addr(),
                    ))
                }
                native::Error::InvalidDescriptor => MapToError::ParentEntryHugePage,
                native::Error::InvalidPermissions => MapToError::InvalidPermissions,
                _ => MapToError::InvalidFrameAddress(frame.start_address()),
            });
        }
        let mut table = self.root as *mut PageTable;
        for level in 0..3 {
            let index = Self::index(page.start_address(), level);
            let current = unsafe { &mut *table };
            let entry = &mut current[index];
            let next = entry.addr();
            entry.set_addr(next, entry.flags() | parent | Flags::PRESENT);
            table = (next.as_u64() + self.offset.as_u64()) as *mut PageTable;
        }
        let current = unsafe { &mut *table };
        current[page.p1_index()].set_addr(frame.start_address(), flags);
        Ok(MapperFlush { page })
    }
    fn translate_page(&self, page: Page) -> Result<PhysFrame, TranslateError> {
        let entry = unsafe { &*self.leaf(page)? };
        if !entry.flags().contains(Flags::PRESENT) {
            return Err(TranslateError::PageNotMapped);
        }
        Ok(PhysFrame::containing_address(entry.addr()))
    }
    fn unmap(&mut self, page: Page) -> Result<(PhysFrame, MapperFlush<Size4KiB>), UnmapError> {
        let entry = self.leaf(page).map_err(|error| match error {
            TranslateError::ParentEntryHugePage => UnmapError::ParentEntryHugePage,
            _ => UnmapError::PageNotMapped,
        })?;
        let entry = unsafe { &mut *entry };
        if !entry.flags().contains(Flags::PRESENT) {
            return Err(UnmapError::PageNotMapped);
        }
        let frame = PhysFrame::containing_address(entry.addr());
        entry.set_unused();
        Ok((frame, MapperFlush { page }))
    }
    unsafe fn update_flags(
        &mut self,
        page: Page,
        flags: Flags,
    ) -> Result<MapperFlush<Size4KiB>, TranslateError> {
        let entry = unsafe { &mut *self.leaf(page)? };
        if entry.is_unused() {
            return Err(TranslateError::PageNotMapped);
        }
        entry.set_addr(entry.addr(), flags);
        Ok(MapperFlush { page })
    }
}

impl Translate for OffsetPageTable<'_> {
    fn translate_addr(&self, address: VirtAddr) -> Option<PhysAddr> {
        let mut table = self.root as *const PageTable;
        for level in 0..4 {
            let entry = &unsafe { &*table }[Self::index(address, level)];
            let flags = entry.flags();
            if !flags.contains(Flags::PRESENT) {
                return None;
            }
            if level == 3 || (level > 0 && flags.contains(Flags::HUGE_PAGE)) {
                let offset = address.as_u64() & ((1u64 << (39 - 9 * level)) - 1);
                return PhysAddr::try_new(entry.addr().as_u64().checked_add(offset)?).ok();
            }
            table = unsafe { self.table(entry.addr()) } as *const PageTable;
        }
        None
    }
}
