use core::mem::size_of;

pub const DOMAIN_BOOT_MAGIC: u64 = u64::from_le_bytes(*b"MNUDOM\0\0");
pub const DOMAIN_BOOT_VERSION: u32 = 8;
pub const DOMAIN_CRASH_MAGIC: u64 = u64::from_le_bytes(*b"MNUCRSH\0");
pub const DOMAIN_CRASH_VERSION: u16 = 1;

pub const HYPERVISOR_BACKEND_INTEL_VMX: u32 = 1;
pub const HYPERVISOR_BACKEND_AMD_SVM: u32 = 2;

pub const DOMAIN_ROLE_SYSTEM: u32 = 1;
pub const DOMAIN_ROLE_HARDWARE: u32 = 2;
pub const DOMAIN_ROLE_APPLICATION: u32 = 3;

pub const DOMAIN_FEATURE_CONSOLE_WRITE: u64 = 1 << 0;
pub const DOMAIN_FEATURE_YIELD: u64 = 1 << 1;
pub const DOMAIN_FEATURE_SHUTDOWN: u64 = 1 << 2;
pub const DOMAIN_FEATURE_READY: u64 = 1 << 3;
pub const DOMAIN_FEATURE_WAIT: u64 = 1 << 4;
pub const DOMAIN_FEATURE_EVENT_CHANNEL: u64 = 1 << 5;
pub const DOMAIN_FEATURE_GRANT_TABLE: u64 = 1 << 6;
pub const DOMAIN_FEATURE_SHARED_RING: u64 = 1 << 7;
pub const DOMAIN_FEATURE_EVENT_IRQ: u64 = 1 << 8;
pub const DOMAIN_FEATURE_VIRTUAL_APIC: u64 = 1 << 9;
pub const DOMAIN_FEATURE_CRASH_QUERY: u64 = 1 << 10;
pub const DOMAIN_FEATURE_DEVICE_QUERY: u64 = 1 << 11;
pub const DOMAIN_FEATURE_DEVICE_OWNERSHIP: u64 = 1 << 12;

pub const DOMAIN_CAPABILITY_DEVICE_QUERY: u64 = 1 << 0;
pub const DOMAIN_CAPABILITY_DEVICE_CLAIM: u64 = 1 << 1;

pub const PCI_DEVICE_STATE_QUARANTINED: u8 = 1;
pub const PCI_DEVICE_STATE_FIRMWARE_DEFERRED: u8 = 2;
pub const PCI_DEVICE_STATE_CLAIMED_DISABLED: u8 = 3;
pub const PCI_DEVICE_FLAG_CLAIMABLE: u32 = 1 << 0;

pub const EVENT_CHANNEL_VECTOR: u8 = 0x40;
pub const DOMAIN_MANAGEMENT_VECTOR: u8 = 0x41;

pub const DOMAIN_CRASH_STATUS_CRASHED: u32 = 1;
pub const DOMAIN_CRASH_STATUS_RESTARTED: u32 = 2;

pub const EVENT_CHANNEL_NO_EVENT: u64 = 0;
pub const GRANT_REF_INVALID: u64 = 0;
pub const GRANT_FLAG_WRITABLE: u64 = 1 << 0;

pub const HYPERCALL_SUCCESS: u64 = 0;
pub const HYPERCALL_UNSUPPORTED: u64 = u64::MAX;
pub const HYPERCALL_INVALID_ARGUMENT: u64 = u64::MAX - 1;

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypercallNumber {
    ConsoleWrite = 0,
    Yield = 1,
    Shutdown = 2,
    Ready = 3,
    Wait = 4,
    EventSend = 5,
    EventWait = 6,
    GrantCreate = 7,
    GrantMap = 8,
    GrantUnmap = 9,
    GrantRevoke = 10,
    EventIrqEnable = 11,
    IrqEoi = 12,
    IrqMask = 13,
    IrqSetTpr = 14,
    DomainCrashQuery = 15,
    DeviceQuery = 16,
    DeviceClaim = 17,
    DeviceRelease = 18,
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    Completed = 0,
    InvalidBootInfo = 1,
    Panic = 2,
    InitializationFailed = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainBootInfoError {
    InvalidMagic,
    UnsupportedVersion,
    InvalidStructSize,
    InvalidBackend,
    InvalidRole,
    MissingRequiredHypercall,
    InvalidMemorySize,
}

/// mBootがmnuの最初のvCPUへ渡す固定長の起動情報です。
///
/// x86_64では、この構造体のゲスト物理アドレスをRDIへ入れて
/// `domain_entry`を呼び出します。アドレスは8バイト境界にそろえます。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainBootInfo {
    pub magic: u64,
    pub abi_version: u32,
    pub struct_size: u32,
    pub domain_id: u32,
    pub vcpu_id: u32,
    pub hypervisor_backend: u32,
    pub domain_role: u32,
    pub memory_size: u64,
    pub feature_flags: u64,
    pub grant_window_start: u64,
    pub grant_window_size: u64,
    pub restart_count: u32,
    pub _reserved0: u32,
    pub capabilities: u64,
}

impl DomainBootInfo {
    pub const fn new(
        domain_id: u32,
        vcpu_id: u32,
        hypervisor_backend: u32,
        domain_role: u32,
        memory_size: u64,
        grant_window_start: u64,
        grant_window_size: u64,
        restart_count: u32,
        capabilities: u64,
    ) -> Self {
        Self {
            magic: DOMAIN_BOOT_MAGIC,
            abi_version: DOMAIN_BOOT_VERSION,
            struct_size: size_of::<Self>() as u32,
            domain_id,
            vcpu_id,
            hypervisor_backend,
            domain_role,
            memory_size,
            feature_flags: DOMAIN_FEATURE_CONSOLE_WRITE
                | DOMAIN_FEATURE_YIELD
                | DOMAIN_FEATURE_SHUTDOWN
                | DOMAIN_FEATURE_READY
                | DOMAIN_FEATURE_WAIT
                | DOMAIN_FEATURE_EVENT_CHANNEL
                | DOMAIN_FEATURE_GRANT_TABLE
                | DOMAIN_FEATURE_SHARED_RING
                | DOMAIN_FEATURE_EVENT_IRQ
                | DOMAIN_FEATURE_VIRTUAL_APIC
                | DOMAIN_FEATURE_CRASH_QUERY
                | DOMAIN_FEATURE_DEVICE_QUERY
                | DOMAIN_FEATURE_DEVICE_OWNERSHIP,
            grant_window_start,
            grant_window_size,
            restart_count,
            _reserved0: 0,
            capabilities,
        }
    }

    pub fn validate(&self) -> Result<(), DomainBootInfoError> {
        if self.magic != DOMAIN_BOOT_MAGIC {
            return Err(DomainBootInfoError::InvalidMagic);
        }
        if self.abi_version != DOMAIN_BOOT_VERSION {
            return Err(DomainBootInfoError::UnsupportedVersion);
        }
        if self.struct_size < size_of::<Self>() as u32 {
            return Err(DomainBootInfoError::InvalidStructSize);
        }
        if !matches!(
            self.hypervisor_backend,
            HYPERVISOR_BACKEND_INTEL_VMX | HYPERVISOR_BACKEND_AMD_SVM
        ) {
            return Err(DomainBootInfoError::InvalidBackend);
        }
        if !matches!(
            self.domain_role,
            DOMAIN_ROLE_SYSTEM | DOMAIN_ROLE_HARDWARE | DOMAIN_ROLE_APPLICATION
        ) {
            return Err(DomainBootInfoError::InvalidRole);
        }
        if self.feature_flags & DOMAIN_FEATURE_SHUTDOWN == 0 {
            return Err(DomainBootInfoError::MissingRequiredHypercall);
        }
        if self.memory_size == 0 || self.memory_size & 0xfff != 0 {
            return Err(DomainBootInfoError::InvalidMemorySize);
        }
        let Some(grant_window_end) = self.grant_window_start.checked_add(self.grant_window_size)
        else {
            return Err(DomainBootInfoError::InvalidMemorySize);
        };
        if self.grant_window_start & 0xfff != 0
            || self.grant_window_size == 0
            || self.grant_window_size & 0xfff != 0
            || grant_window_end > self.memory_size
        {
            return Err(DomainBootInfoError::InvalidMemorySize);
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDeviceInfo {
    pub requester: u16,
    pub class: u8,
    pub subclass: u8,
    pub state: u8,
    pub _reserved0: [u8; 3],
    pub owner_domain: u32,
    pub flags: u32,
}

impl PciDeviceInfo {
    pub fn validate(&self) -> bool {
        self._reserved0 == [0; 3]
            && match self.state {
                PCI_DEVICE_STATE_QUARANTINED => {
                    self.owner_domain == 0 && self.flags & !PCI_DEVICE_FLAG_CLAIMABLE == 0
                }
                PCI_DEVICE_STATE_FIRMWARE_DEFERRED => self.owner_domain == 0 && self.flags == 0,
                PCI_DEVICE_STATE_CLAIMED_DISABLED => self.owner_domain != 0 && self.flags == 0,
                _ => false,
            }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainCrashInfo {
    pub magic: u64,
    pub version: u16,
    pub struct_size: u16,
    pub domain_id: u32,
    pub raw_reason: u64,
    pub fault_address: u64,
    pub fault_info: u64,
    pub restart_count: u32,
    pub status: u32,
}

impl DomainCrashInfo {
    pub const fn new(
        domain_id: u32,
        raw_reason: u64,
        fault_address: u64,
        fault_info: u64,
        restart_count: u32,
        status: u32,
    ) -> Self {
        Self {
            magic: DOMAIN_CRASH_MAGIC,
            version: DOMAIN_CRASH_VERSION,
            struct_size: size_of::<Self>() as u16,
            domain_id,
            raw_reason,
            fault_address,
            fault_info,
            restart_count,
            status,
        }
    }

    pub fn validate(&self) -> bool {
        self.magic == DOMAIN_CRASH_MAGIC
            && self.version == DOMAIN_CRASH_VERSION
            && usize::from(self.struct_size) >= size_of::<Self>()
            && self.domain_id != 0
            && matches!(
                self.status,
                DOMAIN_CRASH_STATUS_CRASHED | DOMAIN_CRASH_STATUS_RESTARTED
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_boot_info_layout_is_fixed() {
        assert_eq!(size_of::<DomainBootInfo>(), 80);
        assert_eq!(core::mem::align_of::<DomainBootInfo>(), 8);
    }

    #[test]
    fn valid_domain_boot_info_is_accepted() {
        let info = DomainBootInfo::new(
            1,
            0,
            HYPERVISOR_BACKEND_AMD_SVM,
            DOMAIN_ROLE_SYSTEM,
            2 * 1024 * 1024,
            0x1f_0000,
            0x1_0000,
            0,
            0,
        );
        assert_eq!(info.validate(), Ok(()));
    }

    #[test]
    fn pci_device_info_layout_is_fixed() {
        assert_eq!(size_of::<PciDeviceInfo>(), 16);
        assert_eq!(core::mem::align_of::<PciDeviceInfo>(), 4);
    }

    #[test]
    fn pci_device_ownership_states_are_consistent() {
        let mut info = PciDeviceInfo {
            requester: 0x10,
            class: 1,
            subclass: 8,
            state: PCI_DEVICE_STATE_QUARANTINED,
            _reserved0: [0; 3],
            owner_domain: 0,
            flags: PCI_DEVICE_FLAG_CLAIMABLE,
        };
        assert!(info.validate());
        info.state = PCI_DEVICE_STATE_CLAIMED_DISABLED;
        info.owner_domain = 2;
        info.flags = 0;
        assert!(info.validate());
        info.owner_domain = 0;
        assert!(!info.validate());
        info.state = PCI_DEVICE_STATE_FIRMWARE_DEFERRED;
        info.flags = PCI_DEVICE_FLAG_CLAIMABLE;
        assert!(!info.validate());
    }

    #[test]
    fn unknown_backend_is_rejected() {
        let mut info = DomainBootInfo::new(
            1,
            0,
            HYPERVISOR_BACKEND_INTEL_VMX,
            DOMAIN_ROLE_SYSTEM,
            4096,
            0,
            4096,
            0,
            0,
        );
        info.hypervisor_backend = 9;
        assert_eq!(info.validate(), Err(DomainBootInfoError::InvalidBackend));
    }

    #[test]
    fn unaligned_memory_size_is_rejected() {
        let info = DomainBootInfo::new(
            1,
            0,
            HYPERVISOR_BACKEND_INTEL_VMX,
            DOMAIN_ROLE_SYSTEM,
            4097,
            0,
            4096,
            0,
            0,
        );
        assert_eq!(info.validate(), Err(DomainBootInfoError::InvalidMemorySize));
    }

    #[test]
    fn unknown_domain_role_is_rejected() {
        let mut info = DomainBootInfo::new(
            1,
            0,
            HYPERVISOR_BACKEND_INTEL_VMX,
            DOMAIN_ROLE_SYSTEM,
            4096,
            0,
            4096,
            0,
            0,
        );
        info.domain_role = 99;
        assert_eq!(info.validate(), Err(DomainBootInfoError::InvalidRole));
    }

    #[test]
    fn crash_info_layout_and_identity_are_fixed() {
        let info = DomainCrashInfo::new(3, 0x400, 0x4000_0000, 4, 1, DOMAIN_CRASH_STATUS_RESTARTED);
        assert_eq!(size_of::<DomainCrashInfo>(), 48);
        assert!(info.validate());
    }
}
