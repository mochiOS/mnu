use core::mem::size_of;
use core::sync::atomic::AtomicU64;

pub const BOOT_ABI_MAGIC: u64 = u64::from_le_bytes(*b"MNUBOOT\0");
pub const BOOT_ABI_VERSION: u32 = 1;
pub const MAX_CPU_IDS: usize = 64;

pub const BOOT_FEATURE_FRAMEBUFFER: u64 = 1 << 0;
pub const BOOT_FEATURE_INITFS: u64 = 1 << 1;
pub const BOOT_FEATURE_ROOTFS_IMAGE: u64 = 1 << 2;
pub const BOOT_FEATURE_SMP: u64 = 1 << 3;
pub const BOOT_FEATURE_ENTROPY: u64 = 1 << 4;
pub const BOOT_FEATURE_HYPERVISOR_DOMAIN: u64 = 1 << 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootInfoError {
    InvalidMagic,
    UnsupportedVersion,
    InvalidStructSize,
    InvalidMemoryMapEntrySize,
    InvalidCpuCount,
}

#[repr(C)]
pub struct SmpHandoff {
    pub ready: AtomicU64,
    pub kernel_secondary_entry: AtomicU64,
    pub boot_info_ptr: AtomicU64,
    pub kernel_cr3: AtomicU64,
    pub ap_count: AtomicU64,
}

impl SmpHandoff {
    pub const fn new() -> Self {
        Self {
            ready: AtomicU64::new(0),
            kernel_secondary_entry: AtomicU64::new(0),
            boot_info_ptr: AtomicU64::new(0),
            kernel_cr3: AtomicU64::new(0),
            ap_count: AtomicU64::new(0),
        }
    }
}

impl Default for SmpHandoff {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Usable = 0,
    Reserved = 1,
    AcpiReclaimable = 2,
    AcpiNvs = 3,
    BadMemory = 4,
    BootloaderReclaimable = 5,
    KernelStack = 6,
    PageTable = 7,
    Framebuffer = 8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub start: u64,
    pub len: u64,
    pub region_type: MemoryType,
}

#[repr(C)]
pub struct BootInfo {
    pub magic: u64,
    pub abi_version: u32,
    pub struct_size: u32,
    pub feature_flags: u64,
    pub physical_memory_offset: u64,
    pub framebuffer_addr: u64,
    pub framebuffer_size: u64,
    pub screen_width: u64,
    pub screen_height: u64,
    pub stride: u64,
    pub memory_map_addr: u64,
    pub memory_map_len: u64,
    pub memory_map_entry_size: u32,
    pub _reserved0: u32,
    pub kernel_heap_addr: u64,
    pub initfs_addr: u64,
    pub initfs_size: u64,
    pub rootfs_addr: u64,
    pub rootfs_size: u64,
    pub cpu_total: u32,
    pub cpu_enabled: u32,
    pub bsp_apic_id: u32,
    pub cpu_apic_ids: [u32; MAX_CPU_IDS],
    pub cpu_apic_id_count: u32,
    pub _reserved1: u32,
    pub smp_handoff_addr: u64,
    pub smp_handoff_size: u32,
    pub _reserved2: u32,
    pub smp_trampoline_addr: u64,
    pub smp_trampoline_size: u64,
    pub entropy_seed: [u8; 32],
    pub entropy_seed_valid: u8,
    pub _reserved3: [u8; 7],
}

impl BootInfo {
    pub const fn empty() -> Self {
        Self {
            magic: BOOT_ABI_MAGIC,
            abi_version: BOOT_ABI_VERSION,
            struct_size: size_of::<Self>() as u32,
            feature_flags: 0,
            physical_memory_offset: 0,
            framebuffer_addr: 0,
            framebuffer_size: 0,
            screen_width: 0,
            screen_height: 0,
            stride: 0,
            memory_map_addr: 0,
            memory_map_len: 0,
            memory_map_entry_size: size_of::<MemoryRegion>() as u32,
            _reserved0: 0,
            kernel_heap_addr: 0,
            initfs_addr: 0,
            initfs_size: 0,
            rootfs_addr: 0,
            rootfs_size: 0,
            cpu_total: 1,
            cpu_enabled: 1,
            bsp_apic_id: 0,
            cpu_apic_ids: [0; MAX_CPU_IDS],
            cpu_apic_id_count: 1,
            _reserved1: 0,
            smp_handoff_addr: 0,
            smp_handoff_size: 0,
            _reserved2: 0,
            smp_trampoline_addr: 0,
            smp_trampoline_size: 0,
            entropy_seed: [0; 32],
            entropy_seed_valid: 0,
            _reserved3: [0; 7],
        }
    }

    pub fn validate(&self) -> Result<(), BootInfoError> {
        if self.magic != BOOT_ABI_MAGIC {
            return Err(BootInfoError::InvalidMagic);
        }
        if self.abi_version != BOOT_ABI_VERSION {
            return Err(BootInfoError::UnsupportedVersion);
        }
        if self.struct_size < size_of::<Self>() as u32 {
            return Err(BootInfoError::InvalidStructSize);
        }
        if self.memory_map_entry_size as usize != size_of::<MemoryRegion>() {
            return Err(BootInfoError::InvalidMemoryMapEntrySize);
        }
        if self.cpu_apic_id_count as usize > MAX_CPU_IDS {
            return Err(BootInfoError::InvalidCpuCount);
        }
        Ok(())
    }
}

impl Default for BootInfo {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_boot_info_is_valid() {
        assert_eq!(BootInfo::empty().validate(), Ok(()));
    }

    #[test]
    fn rejects_unknown_version() {
        let mut info = BootInfo::empty();
        info.abi_version += 1;
        assert_eq!(info.validate(), Err(BootInfoError::UnsupportedVersion));
    }

    #[test]
    fn rejects_short_structure() {
        let mut info = BootInfo::empty();
        info.struct_size -= 1;
        assert_eq!(info.validate(), Err(BootInfoError::InvalidStructSize));
    }
}
