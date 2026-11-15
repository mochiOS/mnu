use core::mem::size_of;
use core::sync::atomic::AtomicU64;

pub const BOOT_ABI_MAGIC: u64 = u64::from_le_bytes(*b"MNUBOOT\0");
pub const BOOT_ABI_VERSION: u32 = 4;
pub const BOOT_ARCH_X86_64: u32 = 1;
pub const BOOT_ARCH_AARCH64: u32 = 2;
#[cfg(target_arch = "x86_64")]
pub const BOOT_NATIVE_ARCH: u32 = BOOT_ARCH_X86_64;
#[cfg(target_arch = "aarch64")]
pub const BOOT_NATIVE_ARCH: u32 = BOOT_ARCH_AARCH64;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const BOOT_NATIVE_ARCH: u32 = 0;
pub const MAX_CPU_IDS: usize = 64;
pub const MAX_BOOT_MEMORY_REGIONS: usize = 256;

pub const BOOT_FEATURE_FRAMEBUFFER: u64 = 1 << 0;
pub const BOOT_FEATURE_INITFS: u64 = 1 << 1;
pub const BOOT_FEATURE_ROOTFS_IMAGE: u64 = 1 << 2;
pub const BOOT_FEATURE_SMP: u64 = 1 << 3;
pub const BOOT_FEATURE_ENTROPY: u64 = 1 << 4;
pub const BOOT_FEATURE_HYPERVISOR_DOMAIN: u64 = 1 << 5;
pub const BOOT_FEATURE_SYSTEM_SLOT: u64 = 1 << 6;
pub const BOOT_FEATURE_BOOT_ESP_GUID: u64 = 1 << 7;
pub const BOOT_FEATURE_ARM64_INTERRUPTS: u64 = 1 << 8;
pub const BOOT_SYSTEM_SLOT_LEGACY: u8 = 0;
pub const BOOT_SYSTEM_SLOT_A: u8 = 1;
pub const BOOT_SYSTEM_SLOT_B: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootInfoError {
    InvalidMagic,
    UnsupportedVersion,
    InvalidStructSize,
    InvalidMemoryMapEntrySize,
    InvalidCpuCount,
    UnsupportedArchitecture,
    InvalidCpuIdentity,
    UnsupportedSmpHandoff,
    InvalidSystemSlot,
    InvalidBootEspGuid,
    InvalidInterruptResources,
}

#[repr(C)]
/// Existing x86 bootstrap handoff. ARM must supply its own native startup
/// state rather than storing TTBR values in a CR3 field.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: u64,
    pub len: u64,
    pub region_type: MemoryType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalRange {
    pub start: u64,
    pub len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryMapTransformError {
    InvalidMemoryRegion,
    InvalidReservedRange,
    OutputTooSmall,
}

fn append_memory_region(
    output: &mut [MemoryRegion],
    output_len: &mut usize,
    region: MemoryRegion,
) -> Result<(), MemoryMapTransformError> {
    if region.len == 0 {
        return Ok(());
    }
    if *output_len != 0 {
        let previous = &mut output[*output_len - 1];
        let previous_end = previous
            .start
            .checked_add(previous.len)
            .ok_or(MemoryMapTransformError::InvalidMemoryRegion)?;
        if previous_end == region.start && previous.region_type == region.region_type {
            previous.len = previous
                .len
                .checked_add(region.len)
                .ok_or(MemoryMapTransformError::InvalidMemoryRegion)?;
            return Ok(());
        }
    }
    let slot = output
        .get_mut(*output_len)
        .ok_or(MemoryMapTransformError::OutputTooSmall)?;
    *slot = region;
    *output_len += 1;
    Ok(())
}

fn next_reserved_range(
    cursor: u64,
    region_end: u64,
    reserved: &[PhysicalRange],
) -> Option<(u64, u64)> {
    let mut next: Option<(u64, u64)> = None;
    for range in reserved {
        let overlap_start = range.start.max(cursor);
        let overlap_end = (range.start + range.len).min(region_end);
        if overlap_start >= overlap_end {
            continue;
        }
        match next {
            Some((best_start, _)) if best_start < overlap_start => {}
            Some((best_start, best_end)) if best_start == overlap_start => {
                next = Some((best_start, best_end.max(overlap_end)));
            }
            _ => next = Some((overlap_start, overlap_end)),
        }
    }
    next
}

/// `BootloaderReclaimable`のうち、`reserved`と重ならないpageを`Usable`へ変換します。
///
/// 入力は変更せず、隣接する同種regionをまとめて`output`へ書き出します。
/// kernel imageやinitfs、起動中のstackなど、引き続き参照する範囲は呼び出し側が
/// page単位で`reserved`へ渡す必要があります。
pub fn build_reclaimed_memory_map(
    input: &[MemoryRegion],
    reserved: &[PhysicalRange],
    output: &mut [MemoryRegion],
) -> Result<usize, MemoryMapTransformError> {
    for range in reserved {
        if range.len == 0
            || range.start & 0xfff != 0
            || range.len & 0xfff != 0
            || range.start.checked_add(range.len).is_none()
        {
            return Err(MemoryMapTransformError::InvalidReservedRange);
        }
    }

    let mut output_len = 0usize;
    for region in input {
        let region_end = region
            .start
            .checked_add(region.len)
            .ok_or(MemoryMapTransformError::InvalidMemoryRegion)?;
        if region.region_type != MemoryType::BootloaderReclaimable {
            append_memory_region(output, &mut output_len, *region)?;
            continue;
        }
        if region.start & 0xfff != 0 || region.len & 0xfff != 0 {
            return Err(MemoryMapTransformError::InvalidMemoryRegion);
        }

        let mut cursor = region.start;
        while cursor < region_end {
            let Some((reserved_start, reserved_end)) =
                next_reserved_range(cursor, region_end, reserved)
            else {
                append_memory_region(
                    output,
                    &mut output_len,
                    MemoryRegion {
                        start: cursor,
                        len: region_end - cursor,
                        region_type: MemoryType::Usable,
                    },
                )?;
                break;
            };
            if cursor < reserved_start {
                append_memory_region(
                    output,
                    &mut output_len,
                    MemoryRegion {
                        start: cursor,
                        len: reserved_start - cursor,
                        region_type: MemoryType::Usable,
                    },
                )?;
            }
            append_memory_region(
                output,
                &mut output_len,
                MemoryRegion {
                    start: reserved_start,
                    len: reserved_end - reserved_start,
                    region_type: MemoryType::Reserved,
                },
            )?;
            cursor = reserved_end;
        }
    }
    Ok(output_len)
}

#[repr(C)]
pub struct BootInfo {
    pub magic: u64,
    pub abi_version: u32,
    pub struct_size: u32,
    pub feature_flags: u64,
    pub architecture: u32,
    pub _reserved_arch: u32,
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
    /// APIC ID on x86, MPIDR affinity (Aff3..Aff0) on AArch64.
    /// Hardware identities are not indices into per-CPU arrays.
    pub bsp_hardware_id: u64,
    pub cpu_hardware_ids: [u64; MAX_CPU_IDS],
    pub cpu_id_count: u32,
    pub _reserved1: u32,
    pub smp_handoff_addr: u64,
    pub smp_handoff_size: u32,
    pub _reserved2: u32,
    pub smp_trampoline_addr: u64,
    pub smp_trampoline_size: u64,
    pub entropy_seed: [u8; 32],
    pub entropy_seed_valid: u8,
    pub system_slot: u8,
    pub _reserved3: [u8; 6],
    /// Canonical GUID bytes of the EFI system partition used to load this image.
    /// Only valid when `BOOT_FEATURE_BOOT_ESP_GUID` is set.
    pub boot_esp_guid: [u8; 16],
    pub arm64_interrupts: super::arm64_interrupts::Resources,
}

impl BootInfo {
    pub const fn empty() -> Self {
        Self {
            magic: BOOT_ABI_MAGIC,
            abi_version: BOOT_ABI_VERSION,
            struct_size: size_of::<Self>() as u32,
            feature_flags: 0,
            architecture: BOOT_NATIVE_ARCH,
            _reserved_arch: 0,
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
            bsp_hardware_id: 0,
            cpu_hardware_ids: [0; MAX_CPU_IDS],
            cpu_id_count: 1,
            _reserved1: 0,
            smp_handoff_addr: 0,
            smp_handoff_size: 0,
            _reserved2: 0,
            smp_trampoline_addr: 0,
            smp_trampoline_size: 0,
            entropy_seed: [0; 32],
            entropy_seed_valid: 0,
            system_slot: BOOT_SYSTEM_SLOT_LEGACY,
            _reserved3: [0; 6],
            boot_esp_guid: [0; 16],
            arm64_interrupts: super::arm64_interrupts::Resources::empty(),
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
        if self.architecture != BOOT_NATIVE_ARCH
            || !matches!(self.architecture, BOOT_ARCH_X86_64 | BOOT_ARCH_AARCH64)
            || self._reserved_arch != 0
        {
            return Err(BootInfoError::UnsupportedArchitecture);
        }
        if self.memory_map_entry_size as usize != size_of::<MemoryRegion>() {
            return Err(BootInfoError::InvalidMemoryMapEntrySize);
        }
        self.validate_cpu_topology()?;
        if self.feature_flags & BOOT_FEATURE_ARM64_INTERRUPTS != 0 {
            if self.architecture != BOOT_ARCH_AARCH64 || !self.arm64_interrupts.valid() {
                return Err(BootInfoError::InvalidInterruptResources);
            }
        } else if self.arm64_interrupts != super::arm64_interrupts::Resources::empty() {
            return Err(BootInfoError::InvalidInterruptResources);
        }
        if self.architecture == BOOT_ARCH_AARCH64
            && (self.feature_flags & BOOT_FEATURE_SMP != 0
                || self.smp_handoff_addr != 0
                || self.smp_handoff_size != 0
                || self.smp_trampoline_addr != 0
                || self.smp_trampoline_size != 0)
        {
            return Err(BootInfoError::UnsupportedSmpHandoff);
        }
        if (self.feature_flags & BOOT_FEATURE_SYSTEM_SLOT) != 0 {
            if self.system_slot != BOOT_SYSTEM_SLOT_A && self.system_slot != BOOT_SYSTEM_SLOT_B {
                return Err(BootInfoError::InvalidSystemSlot);
            }
        } else if self.system_slot != BOOT_SYSTEM_SLOT_LEGACY {
            return Err(BootInfoError::InvalidSystemSlot);
        }
        if (self.feature_flags & BOOT_FEATURE_BOOT_ESP_GUID) != 0 {
            if (self.feature_flags & BOOT_FEATURE_SYSTEM_SLOT) == 0 || self.boot_esp_guid == [0; 16]
            {
                return Err(BootInfoError::InvalidBootEspGuid);
            }
        } else if self.boot_esp_guid != [0; 16] {
            return Err(BootInfoError::InvalidBootEspGuid);
        }
        Ok(())
    }

    fn validate_cpu_topology(&self) -> Result<(), BootInfoError> {
        let ids = self
            .cpu_hardware_ids
            .get(..self.cpu_id_count as usize)
            .ok_or(BootInfoError::InvalidCpuCount)?;
        if self.cpu_enabled == 0 || self.cpu_total < self.cpu_enabled {
            return Err(BootInfoError::InvalidCpuCount);
        }
        let mask = match self.architecture {
            BOOT_ARCH_X86_64 => u64::from(u32::MAX),
            BOOT_ARCH_AARCH64 => 0x0000_00ff_00ff_ffff,
            _ => return Err(BootInfoError::UnsupportedArchitecture),
        };
        if self.bsp_hardware_id & !mask != 0
            || ids
                .iter()
                .enumerate()
                .any(|(index, &id)| id & !mask != 0 || ids[..index].contains(&id))
            || !ids.is_empty() && !ids.contains(&self.bsp_hardware_id)
        {
            return Err(BootInfoError::InvalidCpuIdentity);
        }
        Ok(())
    }

    /// Look up the logical slot without truncating a hardware affinity ID.
    /// Call validate() before consuming any other boot metadata.
    pub fn cpu_slot(&self, hardware_id: u64) -> Option<usize> {
        self.cpu_hardware_ids
            .get(..self.cpu_id_count as usize)?
            .iter()
            .position(|&id| id == hardware_id)
    }
}

impl Default for BootInfo {
    fn default() -> Self {
        Self::empty()
    }
}

const _: () = assert!(size_of::<BootInfo>() == 832);
const _: () = assert!(core::mem::offset_of!(BootInfo, cpu_hardware_ids) == 160);

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_REGION: MemoryRegion = MemoryRegion {
        start: 0,
        len: 0,
        region_type: MemoryType::Reserved,
    };

    const fn region(start: u64, len: u64, region_type: MemoryType) -> MemoryRegion {
        MemoryRegion {
            start,
            len,
            region_type,
        }
    }

    #[test]
    fn empty_boot_info_is_valid() {
        assert_eq!(BootInfo::empty().validate(), Ok(()));
    }

    #[test]
    fn interrupt_resources_require_explicit_native_feature_admission() {
        let mut info = BootInfo::empty();
        info.arm64_interrupts = super::super::arm64_interrupts::Resources::gic_v2(
            0x1000_0000, 27, 64, 65, 1, 2,
        );
        assert_eq!(info.validate(), Err(BootInfoError::InvalidInterruptResources));
        info.feature_flags |= BOOT_FEATURE_ARM64_INTERRUPTS;
        if BOOT_NATIVE_ARCH == BOOT_ARCH_AARCH64 {
            assert_eq!(info.validate(), Ok(()));
            info.arm64_interrupts.reserved = 1;
        }
        assert_eq!(info.validate(), Err(BootInfoError::InvalidInterruptResources));
    }

    #[test]
    fn rejects_foreign_boot_architecture_and_reserved_bits() {
        let mut info = BootInfo::empty();
        info.architecture = if BOOT_NATIVE_ARCH == BOOT_ARCH_X86_64 {
            BOOT_ARCH_AARCH64
        } else {
            BOOT_ARCH_X86_64
        };
        assert_eq!(info.validate(), Err(BootInfoError::UnsupportedArchitecture));
        info.architecture = BOOT_NATIVE_ARCH;
        info._reserved_arch = 1;
        assert_eq!(info.validate(), Err(BootInfoError::UnsupportedArchitecture));
        info._reserved_arch = 0;
        info.abi_version = 2;
        assert_eq!(info.validate(), Err(BootInfoError::UnsupportedVersion));
    }

    #[test]
    fn arm_affinity_ids_keep_aff3_and_use_logical_slots() {
        let mut info = BootInfo::empty();
        info.architecture = BOOT_ARCH_AARCH64;
        info.cpu_total = 2;
        info.cpu_enabled = 2;
        info.cpu_id_count = 2;
        info.bsp_hardware_id = 0x1200_000001;
        info.cpu_hardware_ids[..2].copy_from_slice(&[0x1200_000001, 0x3400_020003]);
        assert_eq!(info.validate_cpu_topology(), Ok(()));
        assert_eq!(info.cpu_slot(0x1200_000001), Some(0));
        assert_eq!(info.cpu_slot(0x3400_020003), Some(1));
        assert_eq!(info.cpu_slot(1), None);
        info.cpu_hardware_ids[1] |= 1 << 24; // MT is not an affinity bit.
        assert_eq!(
            info.validate_cpu_topology(),
            Err(BootInfoError::InvalidCpuIdentity)
        );
    }

    #[test]
    fn rejects_ambiguous_topology_and_truncated_x86_ids() {
        let mut info = BootInfo::empty();
        info.architecture = BOOT_ARCH_X86_64;
        info.cpu_id_count = 2;
        assert_eq!(
            info.validate_cpu_topology(),
            Err(BootInfoError::InvalidCpuIdentity)
        );
        info.cpu_hardware_ids[1] = 1 << 32;
        assert_eq!(
            info.validate_cpu_topology(),
            Err(BootInfoError::InvalidCpuIdentity)
        );
        info.cpu_hardware_ids[1] = 3;
        info.bsp_hardware_id = 2;
        assert_eq!(
            info.validate_cpu_topology(),
            Err(BootInfoError::InvalidCpuIdentity)
        );
        info.cpu_id_count = (MAX_CPU_IDS + 1) as u32;
        assert_eq!(
            info.validate_cpu_topology(),
            Err(BootInfoError::InvalidCpuCount)
        );
        assert_eq!(info.cpu_slot(0), None);
    }

    #[test]
    fn system_slot_requires_feature_and_known_value() {
        let mut info = BootInfo::empty();
        info.system_slot = BOOT_SYSTEM_SLOT_A;
        assert_eq!(info.validate(), Err(BootInfoError::InvalidSystemSlot));
        info.feature_flags |= BOOT_FEATURE_SYSTEM_SLOT;
        assert_eq!(info.validate(), Ok(()));
        info.system_slot = BOOT_SYSTEM_SLOT_B;
        assert_eq!(info.validate(), Ok(()));
        info.system_slot = BOOT_SYSTEM_SLOT_LEGACY;
        assert_eq!(info.validate(), Err(BootInfoError::InvalidSystemSlot));
    }

    #[test]
    fn boot_esp_guid_requires_ab_slot_and_explicit_feature() {
        let mut info = BootInfo::empty();
        info.boot_esp_guid = [1; 16];
        assert_eq!(info.validate(), Err(BootInfoError::InvalidBootEspGuid));
        info.feature_flags |= BOOT_FEATURE_BOOT_ESP_GUID;
        assert_eq!(info.validate(), Err(BootInfoError::InvalidBootEspGuid));
        info.system_slot = BOOT_SYSTEM_SLOT_B;
        info.feature_flags |= BOOT_FEATURE_SYSTEM_SLOT;
        assert_eq!(info.validate(), Ok(()));
        info.boot_esp_guid = [0; 16];
        assert_eq!(info.validate(), Err(BootInfoError::InvalidBootEspGuid));
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

    #[test]
    fn reclaims_unreserved_bootloader_pages() {
        let input = [region(0x1000, 0x4000, MemoryType::BootloaderReclaimable)];
        let mut output = [EMPTY_REGION; 1];

        let len = build_reclaimed_memory_map(&input, &[], &mut output).unwrap();

        assert_eq!(len, 1);
        assert_eq!(output[0], region(0x1000, 0x4000, MemoryType::Usable));
    }

    #[test]
    fn preserves_a_reserved_region_starting_at_zero() {
        let input = [
            region(0, 0x1000, MemoryType::Reserved),
            region(0x1000, 0x1000, MemoryType::BootloaderReclaimable),
        ];
        let mut output = [EMPTY_REGION; 2];

        let len = build_reclaimed_memory_map(&input, &[], &mut output).unwrap();

        assert_eq!(len, 2);
        assert_eq!(output[0], region(0, 0x1000, MemoryType::Reserved));
        assert_eq!(output[1], region(0x1000, 0x1000, MemoryType::Usable));
    }

    #[test]
    fn keeps_reserved_pages_out_of_reclaimed_memory() {
        let input = [region(0x1000, 0x8000, MemoryType::BootloaderReclaimable)];
        let reserved = [
            PhysicalRange {
                start: 0x3000,
                len: 0x2000,
            },
            PhysicalRange {
                start: 0x4000,
                len: 0x3000,
            },
        ];
        let mut output = [EMPTY_REGION; 3];

        let len = build_reclaimed_memory_map(&input, &reserved, &mut output).unwrap();

        assert_eq!(len, 3);
        assert_eq!(output[0], region(0x1000, 0x2000, MemoryType::Usable));
        assert_eq!(output[1], region(0x3000, 0x4000, MemoryType::Reserved));
        assert_eq!(output[2], region(0x7000, 0x2000, MemoryType::Usable));
    }

    #[test]
    fn reports_insufficient_output_capacity() {
        let input = [region(0x1000, 0x3000, MemoryType::BootloaderReclaimable)];
        let reserved = [PhysicalRange {
            start: 0x2000,
            len: 0x1000,
        }];
        let mut output = [EMPTY_REGION; 2];

        assert_eq!(
            build_reclaimed_memory_map(&input, &reserved, &mut output),
            Err(MemoryMapTransformError::OutputTooSmall)
        );
    }
}
