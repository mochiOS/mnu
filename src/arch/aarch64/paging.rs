//! AArch64 EL1 stage-1 mechanism: 4-KiB pages, 48-bit VAs, base FP/SIMD CPUs.
//! Allocation, mapping ownership, backing objects and admission stay in mem/.
use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

pub const PAGE_SIZE: u64 = 4096;
const ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;
const VALID_TABLE_OR_PAGE: u64 = 3;
const AF: u64 = 1 << 10;
const INNER_SHAREABLE: u64 = 3 << 8;
const USER: u64 = 1 << 6;
const READ_ONLY: u64 = 1 << 7;
const NOT_GLOBAL: u64 = 1 << 11;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    UnsupportedCpu,
    InvalidAddress,
    InvalidDescriptor,
    InvalidPermissions,
    AlreadyMapped,
    NotMapped,
    OutOfMemory,
    MmuAlreadyEnabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Normal,
    Device,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    pub user: bool,
    pub writable: bool,
    pub executable: bool,
    pub memory: MemoryType,
}

impl Access {
    fn descriptor(self, physical: u64) -> Result<u64, Error> {
        if self.executable && (self.writable || self.memory == MemoryType::Device) {
            return Err(Error::InvalidPermissions);
        }
        let mut value = physical | VALID_TABLE_OR_PAGE | AF | INNER_SHAREABLE;
        if self.user {
            value |= USER | NOT_GLOBAL;
        }
        if !self.writable {
            value |= READ_ONLY;
        }
        if self.user || !self.executable {
            value |= PXN;
        }
        if !self.user || !self.executable {
            value |= UXN;
        }
        if self.memory == MemoryType::Device {
            value |= 1 << 2;
        }
        Ok(value)
    }
}

#[repr(C, align(4096))]
pub struct PageTable {
    entries: [u64; 512],
}

impl PageTable {
    pub const fn zeroed() -> Self {
        Self { entries: [0; 512] }
    }

    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            // SAFETY: Exclusive access to this owned table; volatile stores
            // keep clearing explicit for the hardware page-table walker.
            unsafe { write_volatile(entry, 0) };
        }
    }
}

/// Memory access to exclusively owned page-table frames.
///
/// # Safety
/// Allocated frames must be unique, zeroed, aligned and pinned until freed.
/// `table_ptr` must resolve every allocated/live root or child to valid writable
/// kernel memory, without aliasing unrelated frames. Mutations require the VM
/// layer's mapping lock and quiescence of affected users. It must not free a
/// table still in use by any CPU, hardware walker or another address space.
pub unsafe trait TableMemory {
    fn allocate_table(&mut self) -> Result<u64, Error>;
    unsafe fn free_table(&mut self, physical: u64);
    unsafe fn table_ptr(&self, physical: u64) -> *mut PageTable;
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    physical_bits: u8,
    ips: u64,
}

impl Config {
    /// Detect a supported 4-KiB stage-1 configuration on this privileged CPU.
    pub fn detect() -> Result<Self, Error> {
        let features: u64;
        // SAFETY: Architecture initialization runs at EL1, not from EL0.
        unsafe {
            asm!("mrs {}, id_aa64mmfr0_el1", out(reg) features, options(nomem, nostack));
        }
        if (features >> 28) & 15 > 1 {
            return Err(Error::UnsupportedCpu);
        }
        let ips = features & 15;
        let bits = match ips {
            0 => 32,
            1 => 36,
            2 => 40,
            3 => 42,
            4 => 44,
            5 | 6 => 48,
            _ => return Err(Error::UnsupportedCpu),
        };
        Ok(Self {
            physical_bits: bits,
            ips: ips.min(5),
        })
    }

    fn check_frame(self, physical: u64) -> Result<(), Error> {
        if physical & (PAGE_SIZE - 1) != 0 || physical >= 1u64 << self.physical_bits {
            return Err(Error::InvalidAddress);
        }
        Ok(())
    }

    /// Enable a fresh stage-1 regime. Does not discover platform memory/devices.
    ///
    /// # Safety
    /// Run at EL1h with exceptions masked and MMU off. Both roots and all walk
    /// frames must remain pinned. The current PC, stack, vectors and all memory
    /// used after enabling must have suitable mappings at their current VAs.
    /// All CPUs sharing these tables must use the same MAIR/TCR configuration.
    pub unsafe fn enable(self, lower_root: u64, upper_root: u64) -> Result<(), Error> {
        self.check_frame(lower_root)?;
        self.check_frame(upper_root)?;
        let mut control: u64;
        unsafe {
            asm!("mrs {}, sctlr_el1", out(reg) control, options(nomem, nostack));
        }
        if control & 1 != 0 {
            return Err(Error::MmuAlreadyEnabled);
        }
        if control & ((1 << 24) | (1 << 25)) != 0 {
            return Err(Error::UnsupportedCpu);
        }
        // 48-bit TTBR0/TTBR1, 4 KiB, inner-shareable WBWA walks, 8-bit ASIDs.
        let tcr = 16u64
            | (1 << 8)
            | (1 << 10)
            | (3 << 12)
            | (16 << 16)
            | (1 << 24)
            | (1 << 26)
            | (3 << 28)
            | (2 << 30)
            | (self.ips << 32);
        // Preserve architectural RES1 and existing control bits. Enforce WXN,
        // aligned stacks, and trap EL0 WFI/WFE/cache maintenance by default.
        control |= 1 | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 12) | (1 << 19);
        control &= !((1 << 16) | (1 << 18) | (1 << 26));
        unsafe {
            asm!(
                "dsb sy", "msr mair_el1, {mair}", "msr tcr_el1, {tcr}", "isb",
                "msr ttbr0_el1, {lower}", "msr ttbr1_el1, {upper}",
                "tlbi vmalle1is", "dsb ish", "isb", "msr sctlr_el1, {control}", "isb",
                mair = in(reg) 0xffu64, tcr = in(reg) tcr,
                lower = in(reg) lower_root, upper = in(reg) upper_root,
                control = in(reg) control, options(nostack),
            );
        }
        Ok(())
    }

    /// Switch TTBR0 without invalidating other live ASIDs.
    ///
    /// # Safety
    /// All current kernel mappings and the executing stack must remain valid.
    /// The caller owns this root and ASID; reuse requires completed invalidation
    /// on every sharing CPU. Mapping ownership/lifetimes are a VM-layer duty.
    pub unsafe fn switch_lower_root(self, root: u64, asid: u8) -> Result<(), Error> {
        self.check_frame(root)?;
        unsafe {
            asm!("dsb ishst", "msr ttbr0_el1, {}", "isb", in(reg) root | (u64::from(asid) << 48), options(nostack));
        }
        Ok(())
    }
}

fn indices(address: u64) -> Result<[usize; 4], Error> {
    if address & 0xfff != 0 || !(address < 1u64 << 48 || address >= 0xffff_0000_0000_0000) {
        return Err(Error::InvalidAddress);
    }
    Ok([
        ((address >> 39) & 511) as usize,
        ((address >> 30) & 511) as usize,
        ((address >> 21) & 511) as usize,
        ((address >> 12) & 511) as usize,
    ])
}

/// Broadcast completion of a leaf removal/replacement, including global entries.
/// # Safety
/// Must execute at EL1 in the same inner-shareable translation domain as users.
pub unsafe fn invalidate_page(address: u64) {
    unsafe {
        asm!("dsb ishst", "tlbi vaae1is, {}", "dsb ish", "isb",
            in(reg) (address >> 12) & ((1u64 << 44) - 1), options(nostack));
    }
}

/// # Safety
/// The caller must prevent new uses of this ASID until invalidation completes.
pub unsafe fn invalidate_asid(asid: u8) {
    unsafe {
        asm!("dsb ishst", "tlbi aside1is, {}", "dsb ish", "isb",
            in(reg) u64::from(asid) << 48, options(nostack));
    }
}

/// Page-table editing over the VM layer's allocation/mapping ownership.
pub struct Mapper<'a, M: TableMemory> {
    root: u64,
    config: Config,
    memory: &'a mut M,
}

impl<'a, M: TableMemory> Mapper<'a, M> {
    /// # Safety
    /// The root is a live, exclusively editable table owned through `memory`.
    /// Callers must quiesce affected mappings and retain all frame lifetimes.
    pub unsafe fn new(root: u64, config: Config, memory: &'a mut M) -> Result<Self, Error> {
        config.check_frame(root)?;
        Ok(Self {
            root,
            config,
            memory,
        })
    }

    fn entry(&self, table: u64, index: usize) -> *mut u64 {
        // SAFETY: The trait contract resolves owned tables. Every index comes
        // from a 9-bit VA component and is within the 512-entry table.
        unsafe { core::ptr::addr_of_mut!((*self.memory.table_ptr(table)).entries[index]) }
    }

    fn child(&self, value: u64) -> Result<u64, Error> {
        if value & !ADDRESS_MASK != VALID_TABLE_OR_PAGE {
            return Err(Error::InvalidDescriptor);
        }
        let address = value & ADDRESS_MASK;
        self.config.check_frame(address)?;
        Ok(address)
    }

    /// Install one 4-KiB leaf. Failed allocation publishes no partial path.
    pub fn map(&mut self, address: u64, physical: u64, access: Access) -> Result<(), Error> {
        let index = indices(address)?;
        self.config.check_frame(physical)?;
        let leaf = access.descriptor(physical)?;
        let mut table = self.root;
        for level in 0..3 {
            let slot = self.entry(table, index[level]);
            // SAFETY: The VM lock and TableMemory contract exclude writers.
            let value = unsafe { read_volatile(slot) };
            if value == 0 {
                let mut allocated = [None; 3];
                for next in allocated.iter_mut().take(3 - level) {
                    match self.memory.allocate_table() {
                        Ok(frame) => {
                            *next = Some(frame);
                            if let Err(error) = self.config.check_frame(frame) {
                                for frame in allocated.into_iter().flatten() {
                                    unsafe { self.memory.free_table(frame) };
                                }
                                return Err(error);
                            }
                        }
                        Err(error) => {
                            for frame in allocated.into_iter().flatten() {
                                // SAFETY: These unpublished tables have no users.
                                unsafe { self.memory.free_table(frame) };
                            }
                            return Err(error);
                        }
                    }
                }
                for offset in 0..3 - level {
                    let frame = allocated[offset].ok_or(Error::OutOfMemory)?;
                    let value = if offset + 1 == 3 - level {
                        leaf
                    } else {
                        allocated[offset + 1].ok_or(Error::OutOfMemory)? | VALID_TABLE_OR_PAGE
                    };
                    // SAFETY: Build the entire private path before publishing.
                    unsafe {
                        write_volatile(self.entry(frame, index[level + offset + 1]), value);
                    }
                }
                unsafe {
                    asm!("dsb ishst", options(nostack));
                    write_volatile(
                        slot,
                        allocated[0].ok_or(Error::OutOfMemory)? | VALID_TABLE_OR_PAGE,
                    );
                    invalidate_page(address);
                }
                return Ok(());
            }
            table = self.child(value)?;
        }
        let slot = self.entry(table, index[3]);
        unsafe {
            if read_volatile(slot) != 0 {
                return Err(Error::AlreadyMapped);
            }
            write_volatile(slot, leaf);
            invalidate_page(address);
        }
        Ok(())
    }

    fn leaf(&self, address: u64) -> Result<*mut u64, Error> {
        let index = indices(address)?;
        let mut table = self.root;
        for &part in &index[..3] {
            let value = unsafe { read_volatile(self.entry(table, part)) };
            if value == 0 {
                return Err(Error::NotMapped);
            }
            table = self.child(value)?;
        }
        let slot = self.entry(table, index[3]);
        if unsafe { read_volatile(slot) } & 3 != 3 {
            return Err(Error::NotMapped);
        }
        Ok(slot)
    }

    /// Change permissions with break-before-make and completed broadcast TLBI.
    pub fn protect(&mut self, address: u64, access: Access) -> Result<(), Error> {
        let slot = self.leaf(address)?;
        let old = unsafe { read_volatile(slot) };
        let replacement = access.descriptor(old & ADDRESS_MASK)?;
        unsafe {
            write_volatile(slot, 0);
            invalidate_page(address);
            write_volatile(slot, replacement);
            asm!("dsb ishst", "isb", options(nostack));
        }
        Ok(())
    }

    /// Remove a leaf; the VM layer retains responsibility for the data frame.
    pub fn unmap(&mut self, address: u64) -> Result<u64, Error> {
        let slot = self.leaf(address)?;
        let old = unsafe { read_volatile(slot) };
        unsafe {
            write_volatile(slot, 0);
            invalidate_page(address);
        }
        Ok(old & ADDRESS_MASK)
    }
}

const _: () = {
    assert!(core::mem::size_of::<PageTable>() == PAGE_SIZE as usize);
    assert!(core::mem::align_of::<PageTable>() == PAGE_SIZE as usize);
};
