use super::{PhysAddr, VirtAddr};
use core::{
    marker::PhantomData,
    ops,
    ptr::{read_volatile, write_volatile},
};

pub trait PageSize: Copy + core::fmt::Debug + Eq {
    const SIZE: u64;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Size4KiB {}
impl PageSize for Size4KiB {
    const SIZE: u64 = 4096;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressNotAligned;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page<S: PageSize = Size4KiB> {
    address: VirtAddr,
    _size: PhantomData<S>,
}
impl<S: PageSize> Page<S> {
    pub fn containing_address(address: VirtAddr) -> Self {
        Self {
            address: address.align_down(S::SIZE),
            _size: PhantomData,
        }
    }
    pub fn from_start_address(address: VirtAddr) -> Result<Self, AddressNotAligned> {
        if !address.is_aligned(S::SIZE) {
            return Err(AddressNotAligned);
        }
        Ok(Self::containing_address(address))
    }
    pub fn start_address(self) -> VirtAddr {
        self.address
    }
    pub fn p1_index(self) -> usize {
        self.address.p1_index()
    }
    pub fn range_inclusive(start: Self, end: Self) -> PageRange<S> {
        PageRange {
            next: start.address.as_u64(),
            end: end.address.as_u64(),
            _size: PhantomData,
        }
    }
}
pub struct PageRange<S: PageSize> {
    next: u64,
    end: u64,
    _size: PhantomData<S>,
}
impl<S: PageSize> Iterator for PageRange<S> {
    type Item = Page<S>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next > self.end {
            return None;
        }
        let page = Page::containing_address(VirtAddr::new(self.next));
        match self.next.checked_add(S::SIZE) {
            Some(next) => self.next = next,
            None => {
                self.next = 1;
                self.end = 0;
            }
        }
        Some(page)
    }
}
impl<S: PageSize> ops::Add<u64> for Page<S> {
    type Output = Self;
    fn add(self, rhs: u64) -> Self {
        Self::containing_address(self.address + rhs * S::SIZE)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysFrame<S: PageSize = Size4KiB> {
    address: PhysAddr,
    _size: PhantomData<S>,
}
impl<S: PageSize> PhysFrame<S> {
    pub fn containing_address(address: PhysAddr) -> Self {
        Self {
            address: address.align_down(S::SIZE),
            _size: PhantomData,
        }
    }
    pub fn from_start_address(address: PhysAddr) -> Result<Self, AddressNotAligned> {
        if !address.is_aligned(S::SIZE) {
            return Err(AddressNotAligned);
        }
        Ok(Self::containing_address(address))
    }
    pub fn start_address(self) -> PhysAddr {
        self.address
    }
}
impl<S: PageSize> ops::Add<u64> for PhysFrame<S> {
    type Output = Self;
    fn add(self, rhs: u64) -> Self {
        Self::containing_address(self.address + rhs * S::SIZE)
    }
}

/// Logical VM access/ownership flags. These are never written directly into an
/// ARM descriptor; COW, suspended leaves and residency retain their meanings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageTableFlags(u64);
impl PageTableFlags {
    pub const PRESENT: Self = Self(1);
    pub const WRITABLE: Self = Self(1 << 1);
    pub const USER_ACCESSIBLE: Self = Self(1 << 2);
    pub const WRITE_THROUGH: Self = Self(1 << 3);
    pub const NO_CACHE: Self = Self(1 << 4);
    pub const ACCESSED: Self = Self(1 << 5);
    pub const DIRTY: Self = Self(1 << 6);
    pub const HUGE_PAGE: Self = Self(1 << 7);
    pub const BIT_52: Self = Self(1 << 52);
    pub const NO_EXECUTE: Self = Self(1 << 63);
    pub const fn empty() -> Self {
        Self(0)
    }
    pub const fn bits(self) -> u64 {
        self.0
    }
    pub const fn from_bits_retain(bits: u64) -> Self {
        Self(bits)
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }
}
impl ops::BitOr for PageTableFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
impl ops::BitAnd for PageTableFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}
impl ops::Not for PageTableFlags {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}
impl ops::BitOrAssign for PageTableFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}
impl ops::BitAndAssign for PageTableFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

pub mod page_table {
    use super::*;
    const PHYSICAL: u64 = 0x0000_ffff_ffff_f000;
    const PXN: u64 = 1 << 53;
    const UXN: u64 = 1 << 54;

    #[repr(transparent)]
    pub struct PageTableEntry {
        value: u64,
    }
    impl Clone for PageTableEntry {
        fn clone(&self) -> Self {
            Self { value: self.raw() }
        }
    }
    impl core::fmt::Debug for PageTableEntry {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_tuple("PageTableEntry").field(&self.raw()).finish()
        }
    }
    impl PageTableEntry {
        pub const fn new() -> Self {
            Self { value: 0 }
        }
        fn raw(&self) -> u64 {
            unsafe { read_volatile(&self.value) }
        }
        pub fn is_unused(&self) -> bool {
            self.raw() == 0
        }
        pub fn addr(&self) -> PhysAddr {
            PhysAddr::new(self.raw() & PHYSICAL)
        }
        pub fn flags(&self) -> PageTableFlags {
            let raw = self.raw();
            if raw == 0 {
                return PageTableFlags::empty();
            }
            let mut flags = (raw >> 46) & (7 << 9); // SW[57:55] -> logical [11:9]
            flags |= ((raw >> 58) & 1) << 52;
            if raw & 1 != 0 {
                flags |= PageTableFlags::PRESENT.bits();
            }
            if raw & (1 << 6) != 0 {
                flags |= PageTableFlags::USER_ACCESSIBLE.bits();
            }
            if raw & (1 << 7) == 0 {
                flags |= PageTableFlags::WRITABLE.bits() | PageTableFlags::DIRTY.bits();
            }
            if raw & (1 << 10) != 0 {
                flags |= PageTableFlags::ACCESSED.bits();
            }
            if raw & 3 == 1 {
                flags |= PageTableFlags::HUGE_PAGE.bits();
            }
            let nx = if flags & PageTableFlags::USER_ACCESSIBLE.bits() != 0 {
                UXN
            } else {
                PXN
            };
            if raw & nx != 0 {
                flags |= PageTableFlags::NO_EXECUTE.bits();
            }
            match (raw >> 2) & 7 {
                1 => {
                    flags |= PageTableFlags::NO_CACHE.bits() | PageTableFlags::WRITE_THROUGH.bits()
                }
                2 => flags |= PageTableFlags::NO_CACHE.bits(),
                3 => flags |= PageTableFlags::WRITE_THROUGH.bits(),
                _ => {}
            }
            PageTableFlags::from_bits_retain(flags)
        }
        pub fn set_addr(&mut self, physical: PhysAddr, flags: PageTableFlags) {
            assert!(physical.is_aligned(4096));
            let bits = flags.bits();
            let user = flags.contains(PageTableFlags::USER_ACCESSIBLE);
            let writable = flags.contains(PageTableFlags::WRITABLE);
            let executable = !flags.contains(PageTableFlags::NO_EXECUTE) && !writable;
            let mut raw = physical.as_u64() | (3 << 8) | (1 << 10);
            raw |= (bits & (7 << 9)) << 46;
            raw |= ((bits >> 52) & 1) << 58;
            if flags.contains(PageTableFlags::PRESENT) {
                raw |= if flags.contains(PageTableFlags::HUGE_PAGE) {
                    1
                } else {
                    3
                };
            }
            if user {
                raw |= (1 << 6) | (1 << 11);
            }
            if !writable {
                raw |= 1 << 7;
            }
            if user || !executable {
                raw |= PXN;
            }
            if !user || !executable {
                raw |= UXN;
            }
            let cache = bits & (PageTableFlags::WRITE_THROUGH | PageTableFlags::NO_CACHE).bits();
            raw |= match cache {
                0x18 => 1 << 2,
                0x10 => 2 << 2,
                0x8 => 3 << 2,
                _ => 0,
            };
            // A device descriptor must never become executable.
            if cache == 0x18 {
                raw |= PXN | UXN;
            }
            self.replace(raw);
        }
        pub fn set_unused(&mut self) {
            self.replace(0);
        }
        fn replace(&mut self, raw: u64) {
            let old = self.raw();
            if old == raw {
                return;
            }
            // Permission/software-only changes with unchanged PA/type/memory
            // attributes can be published atomically. Do not temporarily remove
            // a table covering the executing kernel just to change ignored
            // metadata. Other live replacements require break-before-make.
            let permissions = (3 << 6) | (1 << 10) | (1 << 11) | PXN | UXN | (15 << 55);
            let direct = old & 3 == 3
                && raw & 3 == 3
                && (old ^ raw) & !permissions == 0
                && old & !raw & (1 << 11) == 0;
            unsafe {
                if old & 1 != 0 && !direct {
                    write_volatile(&mut self.value, 0);
                    core::arch::asm!(
                        "dsb ishst",
                        "tlbi vmalle1is",
                        "dsb ish",
                        "isb",
                        options(nostack)
                    );
                }
                write_volatile(&mut self.value, raw);
                core::arch::asm!(
                    "dsb ishst",
                    "tlbi vmalle1is",
                    "dsb ish",
                    "isb",
                    options(nostack)
                );
            }
        }
    }

    #[repr(C, align(4096))]
    pub struct PageTable {
        entries: [PageTableEntry; 512],
    }
    impl PageTable {
        pub const fn zeroed() -> Self {
            Self {
                entries: [const { PageTableEntry::new() }; 512],
            }
        }
        /// Clear an exclusively owned table before publishing it to a walker.
        pub fn clear(&mut self) {
            for entry in &mut self.entries {
                unsafe { write_volatile(&mut entry.value, 0) };
            }
        }
        pub fn iter(&self) -> core::slice::Iter<'_, PageTableEntry> {
            self.entries.iter()
        }
        pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, PageTableEntry> {
            self.entries.iter_mut()
        }
        pub(crate) unsafe fn raw_entry(table: *mut Self, index: usize) -> *mut u64 {
            unsafe { core::ptr::addr_of_mut!((*table).entries[index].value) }
        }
    }
    impl ops::Index<usize> for PageTable {
        type Output = PageTableEntry;
        fn index(&self, index: usize) -> &Self::Output {
            &self.entries[index]
        }
    }
    impl ops::IndexMut<usize> for PageTable {
        fn index_mut(&mut self, index: usize) -> &mut Self::Output {
            &mut self.entries[index]
        }
    }
}
pub use page_table::PageTable;

/// # Safety
/// Returned frames must be unique, owned RAM. Deallocation may only receive
/// frames from this allocator after every mapping/walker reference is gone.
pub unsafe trait FrameAllocator<S: PageSize> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<S>>;
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<S>) -> bool;
}

#[path = "mapper.rs"]
pub mod mapper;
pub use mapper::{Mapper, OffsetPageTable};
