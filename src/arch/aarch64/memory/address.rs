use core::{fmt, ops};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidAddress(pub u64);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct VirtAddr(u64);

impl VirtAddr {
    pub const fn is_canonical(address: u64) -> bool {
        address < 1u64 << 48 || address >= 0xffff_0000_0000_0000
    }
    pub const fn try_new(address: u64) -> Result<Self, InvalidAddress> {
        if Self::is_canonical(address) {
            Ok(Self(address))
        } else {
            Err(InvalidAddress(address))
        }
    }
    /// Kernel-internal constructor. Validate untrusted addresses with try_new.
    pub const fn new(address: u64) -> Self {
        assert!(Self::is_canonical(address));
        Self(address)
    }
    pub const fn new_truncate(address: u64) -> Self {
        let low = address & 0x0000_ffff_ffff_ffff;
        Self(if address >> 63 != 0 {
            low | 0xffff_0000_0000_0000
        } else {
            low
        })
    }
    pub const fn zero() -> Self {
        Self(0)
    }
    pub const fn as_u64(self) -> u64 {
        self.0
    }
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
    pub const fn p4_index(self) -> usize {
        ((self.0 >> 39) & 511) as usize
    }
    pub const fn p3_index(self) -> usize {
        ((self.0 >> 30) & 511) as usize
    }
    pub const fn p2_index(self) -> usize {
        ((self.0 >> 21) & 511) as usize
    }
    pub const fn p1_index(self) -> usize {
        ((self.0 >> 12) & 511) as usize
    }
    pub const fn is_aligned(self, align: u64) -> bool {
        self.0 & (align - 1) == 0
    }
    pub const fn align_down(self, align: u64) -> Self {
        Self(self.0 & !(align - 1))
    }
    pub fn align_up(self, align: u64) -> Self {
        Self::new((self.0 + align - 1) & !(align - 1))
    }
    pub fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }
    pub fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    pub const fn try_new(address: u64) -> Result<Self, InvalidAddress> {
        if address < 1u64 << 48 {
            Ok(Self(address))
        } else {
            Err(InvalidAddress(address))
        }
    }
    pub const fn new(address: u64) -> Self {
        assert!(address < 1u64 << 48);
        Self(address)
    }
    pub const fn zero() -> Self {
        Self(0)
    }
    pub const fn as_u64(self) -> u64 {
        self.0
    }
    pub const fn is_aligned(self, align: u64) -> bool {
        self.0 & (align - 1) == 0
    }
    pub const fn align_down(self, align: u64) -> Self {
        Self(self.0 & !(align - 1))
    }
    pub fn align_up(self, align: u64) -> Self {
        Self::new((self.0 + align - 1) & !(align - 1))
    }
}

macro_rules! address_ops {
    ($name:ident) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({:#x})"), self.0)
            }
        }
        impl fmt::LowerHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }
        impl ops::Add<u64> for $name {
            type Output = Self;
            fn add(self, rhs: u64) -> Self {
                Self::new(self.0 + rhs)
            }
        }
        impl ops::Sub<u64> for $name {
            type Output = Self;
            fn sub(self, rhs: u64) -> Self {
                Self::new(self.0 - rhs)
            }
        }
        impl ops::Sub<Self> for $name {
            type Output = u64;
            fn sub(self, rhs: Self) -> u64 {
                self.0 - rhs.0
            }
        }
    };
}
address_ops!(VirtAddr);
address_ops!(PhysAddr);
