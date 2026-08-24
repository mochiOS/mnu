use core::mem::{align_of, size_of};
use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{Ordering, fence};

use mnu_abi::hypervisor::{
    DomainBootInfo, HYPERCALL_SUCCESS, HypercallNumber, PCI_RESOURCE_FLAG_WRITABLE,
    PciDeviceResource,
};

use crate::domain_hypercall::invoke;
use crate::domain_interrupt;

const PCI_STATUS_CAPABILITIES: u32 = 1 << 20;
const PCI_CAP_VENDOR_SPECIFIC: u8 = 0x09;
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_TRANSITIONAL_BLOCK_ID: u16 = 0x1001;
const VIRTIO_MODERN_BLOCK_ID: u16 = 0x1042;

const DEVICE_STATUS_ACKNOWLEDGE: u8 = 1;
const DEVICE_STATUS_DRIVER: u8 = 2;
const DEVICE_STATUS_DRIVER_OK: u8 = 4;
const DEVICE_STATUS_FEATURES_OK: u8 = 8;
const VIRTIO_F_VERSION_1_HIGH: u32 = 1;
const VIRTIO_F_ACCESS_PLATFORM_HIGH: u32 = 1 << 1;
const REQUIRED_FEATURES_HIGH: u32 = VIRTIO_F_VERSION_1_HIGH | VIRTIO_F_ACCESS_PLATFORM_HIGH;

const COMMON_DEVICE_FEATURE_SELECT: u64 = 0;
const COMMON_DEVICE_FEATURE: u64 = 4;
const COMMON_DRIVER_FEATURE_SELECT: u64 = 8;
const COMMON_DRIVER_FEATURE: u64 = 12;
const COMMON_MSIX_CONFIG: u64 = 16;
const COMMON_DEVICE_STATUS: u64 = 20;
const COMMON_QUEUE_SELECT: u64 = 22;
const COMMON_QUEUE_SIZE: u64 = 24;
const COMMON_QUEUE_MSIX_VECTOR: u64 = 26;
const COMMON_QUEUE_ENABLE: u64 = 28;
const COMMON_QUEUE_NOTIFY_OFF: u64 = 30;
const COMMON_QUEUE_DESC: u64 = 32;
const COMMON_QUEUE_DRIVER: u64 = 40;
const COMMON_QUEUE_DEVICE: u64 = 48;
const COMMON_CONFIG_SIZE: u64 = 56;

const QUEUE_SIZE: u16 = 8;
const DEVICE_IRQ_VECTOR: u8 = 0x42;
const DESCRIPTOR_GPA: u64 = 0x14_0000;
const AVAILABLE_GPA: u64 = 0x14_1000;
const USED_GPA: u64 = 0x14_2000;
const REQUEST_GPA: u64 = 0x14_3000;
const DATA_GPA: u64 = 0x14_4000;
const STATUS_GPA: u64 = 0x14_5000;
const DMA_END: u64 = STATUS_GPA + 4096;
const TEST_SECTOR: u64 = 0;
const TEST_MARKER: &[u8] = b"mochiOS virtio-blk DMA test\n";

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;
const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_S_OK: u8 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedDevice,
    InvalidConfiguration,
    MissingCapability,
    MissingResource,
    FeatureNegotiation,
    QueueUnavailable,
    InterruptUnavailable,
    IoFailed,
    UnexpectedData,
}

impl Error {
    pub const fn message(self) -> &'static [u8] {
        match self {
            Self::UnsupportedDevice => b"virtio-blk: unsupported device\n",
            Self::InvalidConfiguration => b"virtio-blk: invalid configuration\n",
            Self::MissingCapability => b"virtio-blk: missing PCI capability\n",
            Self::MissingResource => b"virtio-blk: missing BAR resource\n",
            Self::FeatureNegotiation => b"virtio-blk: feature negotiation failed\n",
            Self::QueueUnavailable => b"virtio-blk: queue unavailable\n",
            Self::InterruptUnavailable => b"virtio-blk: interrupt unavailable\n",
            Self::IoFailed => b"virtio-blk: request failed\n",
            Self::UnexpectedData => b"virtio-blk: unexpected sector data\n",
        }
    }
}

#[derive(Clone, Copy)]
struct MmioRegion {
    address: u64,
    length: u64,
}

#[derive(Clone, Copy)]
struct Transport {
    common: MmioRegion,
    notify: MmioRegion,
    notify_multiplier: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqDescriptor {
    address: u64,
    length: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioBlockRequest {
    request_type: u32,
    reserved: u32,
    sector: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqUsedElement {
    id: u32,
    length: u32,
}

pub const fn is_virtio_block(identity: u32) -> bool {
    let vendor = identity as u16;
    let device = (identity >> 16) as u16;
    vendor == VIRTIO_VENDOR_ID
        && matches!(
            device,
            VIRTIO_TRANSITIONAL_BLOCK_ID | VIRTIO_MODERN_BLOCK_ID
        )
}

pub fn verify(
    boot_info: &DomainBootInfo,
    requester: u16,
    resources: &[PciDeviceResource],
) -> Result<(), Error> {
    if DMA_END > boot_info.device_window_start {
        return Err(Error::InvalidConfiguration);
    }
    let identity = config_read(boot_info, requester, 0)?;
    if !is_virtio_block(identity) {
        return Err(Error::UnsupportedDevice);
    }
    let transport = discover_transport(boot_info, requester, resources)?;
    prepare_queue_memory();
    reset_and_negotiate(transport.common)?;
    let notify_offset = configure_queue(transport.common)?;
    let interrupt_before = domain_interrupt::device_count();
    set_status_bits(transport.common, DEVICE_STATUS_DRIVER_OK)?;
    if transport.common.read_u8(COMMON_DEVICE_STATUS)? & DEVICE_STATUS_DRIVER_OK == 0 {
        return Err(Error::FeatureNegotiation);
    }
    fence(Ordering::Release);
    notify_queue(transport, notify_offset)?;

    for _ in 0..128 {
        if domain_interrupt::device_count() != interrupt_before {
            break;
        }
        if unsafe {
            invoke(
                boot_info.hypervisor_backend,
                HypercallNumber::Yield,
                0,
                0,
                0,
            )
        } != HYPERCALL_SUCCESS
        {
            return Err(Error::InterruptUnavailable);
        }
    }
    if domain_interrupt::device_count() == interrupt_before {
        let used_index = unsafe { read_volatile((USED_GPA + 2) as *const u16) };
        return Err(if used_index == 0 {
            Error::IoFailed
        } else {
            Error::InterruptUnavailable
        });
    }
    fence(Ordering::Acquire);
    validate_completion()?;
    if unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::IrqEoi,
            0,
            0,
            0,
        )
    } != HYPERCALL_SUCCESS
    {
        return Err(Error::InterruptUnavailable);
    }
    transport.common.write_u8(COMMON_DEVICE_STATUS, 0)?;
    if transport.common.read_u8(COMMON_DEVICE_STATUS)? != 0 {
        return Err(Error::IoFailed);
    }
    Ok(())
}

pub const fn device_irq_vector() -> u8 {
    DEVICE_IRQ_VECTOR
}

fn discover_transport(
    boot_info: &DomainBootInfo,
    requester: u16,
    resources: &[PciDeviceResource],
) -> Result<Transport, Error> {
    if config_read(boot_info, requester, 4)? & PCI_STATUS_CAPABILITIES == 0 {
        return Err(Error::MissingCapability);
    }
    let mut capability = (config_read(boot_info, requester, 0x34)? as u8) & !3;
    let mut visited = 0_u64;
    let mut common = None;
    let mut notify = None;
    let mut notify_multiplier = 0;
    while capability >= 0x40 {
        let visited_bit = 1_u64 << (capability / 4);
        if visited & visited_bit != 0 {
            return Err(Error::InvalidConfiguration);
        }
        visited |= visited_bit;
        let header = config_read(boot_info, requester, u16::from(capability))?;
        let next = ((header >> 8) as u8) & !3;
        let capability_length = (header >> 16) as u8;
        let configuration_type = (header >> 24) as u8;
        if header as u8 == PCI_CAP_VENDOR_SPECIFIC {
            if capability_length < 16 {
                return Err(Error::InvalidConfiguration);
            }
            let bar = config_read(boot_info, requester, u16::from(capability) + 4)? as u8;
            let offset = config_read(boot_info, requester, u16::from(capability) + 8)?;
            let length = config_read(boot_info, requester, u16::from(capability) + 12)?;
            match configuration_type {
                VIRTIO_PCI_CAP_COMMON_CFG => {
                    let region = capability_region(resources, bar, offset, length)?;
                    if region.length < COMMON_CONFIG_SIZE {
                        return Err(Error::InvalidConfiguration);
                    }
                    common = Some(region);
                }
                VIRTIO_PCI_CAP_NOTIFY_CFG if capability_length >= 20 => {
                    let region = capability_region(resources, bar, offset, length)?;
                    notify_multiplier =
                        config_read(boot_info, requester, u16::from(capability) + 16)?;
                    notify = Some(region);
                }
                _ => {}
            }
        }
        capability = next;
    }
    let common = common.ok_or(Error::MissingCapability)?;
    let notify = notify.ok_or(Error::MissingCapability)?;
    if notify_multiplier == 0 {
        return Err(Error::InvalidConfiguration);
    }
    Ok(Transport {
        common,
        notify,
        notify_multiplier,
    })
}

fn capability_region(
    resources: &[PciDeviceResource],
    bar: u8,
    offset: u32,
    length: u32,
) -> Result<MmioRegion, Error> {
    let resource = resources
        .iter()
        .find(|resource| resource.bar_index == bar)
        .ok_or(Error::MissingResource)?;
    let end = u64::from(offset)
        .checked_add(u64::from(length))
        .ok_or(Error::InvalidConfiguration)?;
    if length == 0 || end > resource.length || resource.flags & PCI_RESOURCE_FLAG_WRITABLE == 0 {
        return Err(Error::InvalidConfiguration);
    }
    Ok(MmioRegion {
        address: resource
            .guest_address
            .checked_add(u64::from(offset))
            .ok_or(Error::InvalidConfiguration)?,
        length: u64::from(length),
    })
}

fn reset_and_negotiate(common: MmioRegion) -> Result<(), Error> {
    common.write_u8(COMMON_DEVICE_STATUS, 0)?;
    if common.read_u8(COMMON_DEVICE_STATUS)? != 0 {
        return Err(Error::FeatureNegotiation);
    }
    common.write_u8(COMMON_DEVICE_STATUS, DEVICE_STATUS_ACKNOWLEDGE)?;
    if common.read_u8(COMMON_DEVICE_STATUS)? != DEVICE_STATUS_ACKNOWLEDGE {
        return Err(Error::FeatureNegotiation);
    }
    set_status_bits(common, DEVICE_STATUS_DRIVER)?;
    if common.read_u8(COMMON_DEVICE_STATUS)? != DEVICE_STATUS_ACKNOWLEDGE | DEVICE_STATUS_DRIVER {
        return Err(Error::FeatureNegotiation);
    }
    common.write_u32(COMMON_DEVICE_FEATURE_SELECT, 1)?;
    if common.read_u32(COMMON_DEVICE_FEATURE)? & REQUIRED_FEATURES_HIGH != REQUIRED_FEATURES_HIGH {
        return Err(Error::FeatureNegotiation);
    }
    common.write_u32(COMMON_DRIVER_FEATURE_SELECT, 0)?;
    common.write_u32(COMMON_DRIVER_FEATURE, 0)?;
    common.write_u32(COMMON_DRIVER_FEATURE_SELECT, 1)?;
    common.write_u32(COMMON_DRIVER_FEATURE, REQUIRED_FEATURES_HIGH)?;
    set_status_bits(common, DEVICE_STATUS_FEATURES_OK)?;
    if common.read_u8(COMMON_DEVICE_STATUS)? & DEVICE_STATUS_FEATURES_OK == 0 {
        return Err(Error::FeatureNegotiation);
    }
    Ok(())
}

fn configure_queue(common: MmioRegion) -> Result<u16, Error> {
    common.write_u16(COMMON_MSIX_CONFIG, 0)?;
    if common.read_u16(COMMON_MSIX_CONFIG)? == u16::MAX {
        return Err(Error::InterruptUnavailable);
    }
    common.write_u16(COMMON_QUEUE_SELECT, 0)?;
    let maximum_size = common.read_u16(COMMON_QUEUE_SIZE)?;
    if maximum_size < QUEUE_SIZE {
        return Err(Error::QueueUnavailable);
    }
    common.write_u16(COMMON_QUEUE_SIZE, QUEUE_SIZE)?;
    common.write_u16(COMMON_QUEUE_MSIX_VECTOR, 0)?;
    if common.read_u16(COMMON_QUEUE_MSIX_VECTOR)? == u16::MAX {
        return Err(Error::InterruptUnavailable);
    }
    common.write_u64(COMMON_QUEUE_DESC, DESCRIPTOR_GPA)?;
    common.write_u64(COMMON_QUEUE_DRIVER, AVAILABLE_GPA)?;
    common.write_u64(COMMON_QUEUE_DEVICE, USED_GPA)?;
    let notify_offset = common.read_u16(COMMON_QUEUE_NOTIFY_OFF)?;
    common.write_u16(COMMON_QUEUE_ENABLE, 1)?;
    if common.read_u16(COMMON_QUEUE_ENABLE)? != 1 {
        return Err(Error::QueueUnavailable);
    }
    Ok(notify_offset)
}

fn prepare_queue_memory() {
    for address in [
        DESCRIPTOR_GPA,
        AVAILABLE_GPA,
        USED_GPA,
        REQUEST_GPA,
        DATA_GPA,
        STATUS_GPA,
    ] {
        unsafe { write_bytes(address as *mut u8, 0, 4096) };
    }
    let descriptors = DESCRIPTOR_GPA as *mut VirtqDescriptor;
    unsafe {
        write_volatile(
            descriptors,
            VirtqDescriptor {
                address: REQUEST_GPA,
                length: size_of::<VirtioBlockRequest>() as u32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            },
        );
        write_volatile(
            descriptors.add(1),
            VirtqDescriptor {
                address: DATA_GPA,
                length: 512,
                flags: VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
                next: 2,
            },
        );
        write_volatile(
            descriptors.add(2),
            VirtqDescriptor {
                address: STATUS_GPA,
                length: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        );
        write_volatile(
            REQUEST_GPA as *mut VirtioBlockRequest,
            VirtioBlockRequest {
                request_type: VIRTIO_BLK_T_IN,
                reserved: 0,
                sector: TEST_SECTOR,
            },
        );
        write_volatile(STATUS_GPA as *mut u8, 0xff);
        write_volatile((AVAILABLE_GPA + 4) as *mut u16, 0);
        fence(Ordering::Release);
        write_volatile((AVAILABLE_GPA + 2) as *mut u16, 1);
    }
}

fn notify_queue(transport: Transport, queue_offset: u16) -> Result<(), Error> {
    let offset = u64::from(queue_offset)
        .checked_mul(u64::from(transport.notify_multiplier))
        .ok_or(Error::InvalidConfiguration)?;
    transport.notify.write_u16(offset, 0)
}

fn validate_completion() -> Result<(), Error> {
    let used_index = unsafe { read_volatile((USED_GPA + 2) as *const u16) };
    let used = unsafe { read_volatile((USED_GPA + 4) as *const VirtqUsedElement) };
    let status = unsafe { read_volatile(STATUS_GPA as *const u8) };
    if used_index != 1 || used.id != 0 || used.length < 513 || status != VIRTIO_BLK_S_OK {
        return Err(Error::IoFailed);
    }
    for (index, expected) in TEST_MARKER.iter().copied().enumerate() {
        let actual = unsafe { read_volatile((DATA_GPA as *const u8).add(index)) };
        if actual != expected {
            return Err(Error::UnexpectedData);
        }
    }
    Ok(())
}

fn set_status_bits(common: MmioRegion, bits: u8) -> Result<(), Error> {
    let status = common.read_u8(COMMON_DEVICE_STATUS)?;
    common.write_u8(COMMON_DEVICE_STATUS, status | bits)
}

fn config_read(boot_info: &DomainBootInfo, requester: u16, offset: u16) -> Result<u32, Error> {
    if offset > 0xfc || offset & 3 != 0 {
        return Err(Error::InvalidConfiguration);
    }
    let value = unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::DeviceConfigRead,
            u64::from(requester),
            u64::from(offset),
            0,
        )
    };
    u32::try_from(value).map_err(|_| Error::InvalidConfiguration)
}

impl MmioRegion {
    fn pointer<T>(self, offset: u64) -> Result<*mut T, Error> {
        if offset & (align_of::<T>() as u64 - 1) != 0
            || offset
                .checked_add(size_of::<T>() as u64)
                .is_none_or(|end| end > self.length)
        {
            return Err(Error::InvalidConfiguration);
        }
        Ok((self.address + offset) as *mut T)
    }

    fn read_u8(self, offset: u64) -> Result<u8, Error> {
        Ok(unsafe { read_volatile(self.pointer::<u8>(offset)?) })
    }

    fn read_u16(self, offset: u64) -> Result<u16, Error> {
        Ok(unsafe { read_volatile(self.pointer::<u16>(offset)?) })
    }

    fn read_u32(self, offset: u64) -> Result<u32, Error> {
        Ok(unsafe { read_volatile(self.pointer::<u32>(offset)?) })
    }

    fn write_u8(self, offset: u64, value: u8) -> Result<(), Error> {
        unsafe { write_volatile(self.pointer::<u8>(offset)?, value) };
        Ok(())
    }

    fn write_u16(self, offset: u64, value: u16) -> Result<(), Error> {
        unsafe { write_volatile(self.pointer::<u16>(offset)?, value) };
        Ok(())
    }

    fn write_u32(self, offset: u64, value: u32) -> Result<(), Error> {
        unsafe { write_volatile(self.pointer::<u32>(offset)?, value) };
        Ok(())
    }

    fn write_u64(self, offset: u64, value: u64) -> Result<(), Error> {
        self.write_u32(offset, value as u32)?;
        self.write_u32(offset + 4, (value >> 32) as u32)
    }
}
