use plugkit_sys::PciConfig;

use super::device::DeviceStatus;
use super::error::{VirtioError, VirtioResult};
use super::feature::FeatureSet;

const PCI_CAPABILITY_POINTER: usize = 0x34;
const PCI_CAPABILITY_VENDOR_SPECIFIC: u8 = 0x09;
const VIRTIO_PCI_CAP_MIN_LENGTH: u8 = 16;
const VIRTIO_PCI_NOTIFY_CAP_LENGTH: u8 = 20;
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

const COMMON_DEVICE_FEATURE_SELECT: u32 = 0;
const COMMON_DEVICE_FEATURE: u32 = 4;
const COMMON_DRIVER_FEATURE_SELECT: u32 = 8;
const COMMON_DRIVER_FEATURE: u32 = 12;
const COMMON_DEVICE_STATUS: u32 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciBar {
    pub index: u8,
    pub address: u64,
    pub size: u64,
    pub is_io: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityRegion {
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
}

impl CapabilityRegion {
    fn validate(self, bars: &[PciBar]) -> VirtioResult<Self> {
        let bar = bars
            .iter()
            .find(|candidate| candidate.index == self.bar)
            .ok_or(VirtioError::InvalidBar)?;
        if bar.is_io {
            return Err(VirtioError::BarIsIo);
        }
        let end = u64::from(self.offset)
            .checked_add(u64::from(self.length))
            .ok_or(VirtioError::RegionOverflow)?;
        if self.length == 0 || end > bar.size || bar.address.checked_add(end).is_none() {
            return Err(VirtioError::RegionOverflow);
        }
        Ok(self)
    }

    fn contains(self, offset: u32, size: u32) -> bool {
        offset
            .checked_add(size)
            .is_some_and(|end| end <= self.length)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioPciCapabilities {
    pub common: CapabilityRegion,
    pub notify: CapabilityRegion,
    pub notify_off_multiplier: u32,
    pub isr: CapabilityRegion,
    pub device: Option<CapabilityRegion>,
}

impl VirtioPciCapabilities {
    pub fn parse(config: &PciConfig, bars: &[PciBar]) -> VirtioResult<Self> {
        let mut pointer = config
            .read_u8(PCI_CAPABILITY_POINTER)
            .map_err(|_| VirtioError::InvalidPciCapabilityList)?;
        let mut visited = [false; 256];
        let mut common = None;
        let mut notify = None;
        let mut notify_off_multiplier = 0;
        let mut isr = None;
        let mut device = None;

        while pointer != 0 {
            let offset = usize::from(pointer);
            if offset < 0x40 || offset & 3 != 0 {
                return Err(VirtioError::InvalidPciCapabilityList);
            }
            if visited[offset] {
                return Err(VirtioError::CapabilityLoop);
            }
            visited[offset] = true;
            let id = config
                .read_u8(offset)
                .map_err(|_| VirtioError::InvalidPciCapabilityList)?;
            let next = config
                .read_u8(offset + 1)
                .map_err(|_| VirtioError::InvalidPciCapabilityList)?;
            if id == PCI_CAPABILITY_VENDOR_SPECIFIC {
                let cap_len = config
                    .read_u8(offset + 2)
                    .map_err(|_| VirtioError::InvalidCapabilityLength)?;
                if cap_len < VIRTIO_PCI_CAP_MIN_LENGTH {
                    return Err(VirtioError::InvalidCapabilityLength);
                }
                let cfg_type = config
                    .read_u8(offset + 3)
                    .map_err(|_| VirtioError::InvalidCapabilityLength)?;
                let region = CapabilityRegion {
                    bar: config
                        .read_u8(offset + 4)
                        .map_err(|_| VirtioError::InvalidCapabilityLength)?,
                    offset: config
                        .read_u32(offset + 8)
                        .map_err(|_| VirtioError::InvalidCapabilityLength)?,
                    length: config
                        .read_u32(offset + 12)
                        .map_err(|_| VirtioError::InvalidCapabilityLength)?,
                }
                .validate(bars)?;
                match cfg_type {
                    VIRTIO_PCI_CAP_COMMON_CFG => common = Some(region),
                    VIRTIO_PCI_CAP_NOTIFY_CFG => {
                        if cap_len < VIRTIO_PCI_NOTIFY_CAP_LENGTH {
                            return Err(VirtioError::InvalidCapabilityLength);
                        }
                        notify_off_multiplier = config
                            .read_u32(offset + 16)
                            .map_err(|_| VirtioError::InvalidCapabilityLength)?;
                        notify = Some(region);
                    }
                    VIRTIO_PCI_CAP_ISR_CFG => isr = Some(region),
                    VIRTIO_PCI_CAP_DEVICE_CFG => device = Some(region),
                    _ => {}
                }
            }
            pointer = next;
        }

        Ok(Self {
            common: common.ok_or(VirtioError::MissingCommonConfiguration)?,
            notify: notify.ok_or(VirtioError::MissingNotifyConfiguration)?,
            notify_off_multiplier,
            isr: isr.ok_or(VirtioError::MissingIsrConfiguration)?,
            device,
        })
    }
}

pub trait PciTransportAccess {
    fn read_u8(&mut self, bar: u8, offset: u32) -> VirtioResult<u8>;
    fn read_u32(&mut self, bar: u8, offset: u32) -> VirtioResult<u32>;
    fn write_u8(&mut self, bar: u8, offset: u32, value: u8) -> VirtioResult<()>;
    fn write_u32(&mut self, bar: u8, offset: u32, value: u32) -> VirtioResult<()>;
}

pub struct VirtioPciTransport<A> {
    capabilities: VirtioPciCapabilities,
    access: A,
}

impl<A: PciTransportAccess> VirtioPciTransport<A> {
    pub const fn new(capabilities: VirtioPciCapabilities, access: A) -> Self {
        Self {
            capabilities,
            access,
        }
    }

    pub const fn capabilities(&self) -> &VirtioPciCapabilities {
        &self.capabilities
    }

    pub fn access(&self) -> &A {
        &self.access
    }

    pub fn access_mut(&mut self) -> &mut A {
        &mut self.access
    }

    fn common_offset(&self, offset: u32, size: u32) -> VirtioResult<(u8, u32)> {
        if !self.capabilities.common.contains(offset, size) {
            return Err(VirtioError::RegisterOutOfBounds);
        }
        let absolute = self
            .capabilities
            .common
            .offset
            .checked_add(offset)
            .ok_or(VirtioError::RegionOverflow)?;
        Ok((self.capabilities.common.bar, absolute))
    }

    pub fn read_status(&mut self) -> VirtioResult<DeviceStatus> {
        let (bar, offset) = self.common_offset(COMMON_DEVICE_STATUS, 1)?;
        self.access
            .read_u8(bar, offset)
            .map(DeviceStatus::from_bits)
    }

    pub fn write_status(&mut self, status: DeviceStatus) -> VirtioResult<()> {
        let (bar, offset) = self.common_offset(COMMON_DEVICE_STATUS, 1)?;
        self.access.write_u8(bar, offset, status.bits())
    }

    pub fn read_device_features(&mut self) -> VirtioResult<FeatureSet> {
        let (select_bar, select_offset) = self.common_offset(COMMON_DEVICE_FEATURE_SELECT, 4)?;
        let (feature_bar, feature_offset) = self.common_offset(COMMON_DEVICE_FEATURE, 4)?;
        self.access.write_u32(select_bar, select_offset, 0)?;
        let low = self.access.read_u32(feature_bar, feature_offset)?;
        self.access.write_u32(select_bar, select_offset, 1)?;
        let high = self.access.read_u32(feature_bar, feature_offset)?;
        Ok(FeatureSet::new(u64::from(low) | (u64::from(high) << 32)))
    }

    pub fn write_driver_features(&mut self, features: FeatureSet) -> VirtioResult<()> {
        let (select_bar, select_offset) = self.common_offset(COMMON_DRIVER_FEATURE_SELECT, 4)?;
        let (feature_bar, feature_offset) = self.common_offset(COMMON_DRIVER_FEATURE, 4)?;
        self.access.write_u32(select_bar, select_offset, 0)?;
        self.access
            .write_u32(feature_bar, feature_offset, features.bits() as u32)?;
        self.access.write_u32(select_bar, select_offset, 1)?;
        self.access
            .write_u32(feature_bar, feature_offset, (features.bits() >> 32) as u32)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use plugkit_sys::PciConfig;

    use super::*;
    use crate::virtio::{DeviceStatus, FeatureSet, VIRTIO_F_VERSION_1, VirtioDevice};

    fn put_cap(
        config: &mut [u8],
        offset: usize,
        next: u8,
        length: u8,
        kind: u8,
        bar: u8,
        bar_offset: u32,
        bar_length: u32,
    ) {
        config[offset] = PCI_CAPABILITY_VENDOR_SPECIFIC;
        config[offset + 1] = next;
        config[offset + 2] = length;
        config[offset + 3] = kind;
        config[offset + 4] = bar;
        config[offset + 8..offset + 12].copy_from_slice(&bar_offset.to_le_bytes());
        config[offset + 12..offset + 16].copy_from_slice(&bar_length.to_le_bytes());
    }

    fn valid_capabilities() -> (PciConfig, [PciBar; 1]) {
        let mut config = vec![0u8; 256];
        config[PCI_CAPABILITY_POINTER] = 0x40;
        put_cap(&mut config, 0x40, 0x54, 16, 1, 0, 0x000, 0x100);
        put_cap(&mut config, 0x54, 0x68, 20, 2, 0, 0x100, 0x100);
        config[0x64..0x68].copy_from_slice(&4u32.to_le_bytes());
        put_cap(&mut config, 0x68, 0x78, 16, 3, 0, 0x200, 0x20);
        put_cap(&mut config, 0x78, 0, 16, 4, 0, 0x300, 0x100);
        (
            PciConfig::new(config),
            [PciBar {
                index: 0,
                address: 0x1000_0000,
                size: 0x1000,
                is_io: false,
            }],
        )
    }

    #[derive(Clone)]
    struct MockAccess {
        bytes: Vec<u8>,
        device_features: u64,
        device_feature_page: u32,
        driver_feature_page: u32,
        driver_features: u64,
        reject_features: bool,
    }

    impl MockAccess {
        fn new(device_features: u64) -> Self {
            Self {
                bytes: vec![0; 0x1000],
                device_features,
                device_feature_page: 0,
                driver_feature_page: 0,
                driver_features: 0,
                reject_features: false,
            }
        }
    }

    impl PciTransportAccess for MockAccess {
        fn read_u8(&mut self, _bar: u8, offset: u32) -> VirtioResult<u8> {
            self.bytes
                .get(offset as usize)
                .copied()
                .ok_or(VirtioError::AccessFailed)
        }

        fn read_u32(&mut self, _bar: u8, offset: u32) -> VirtioResult<u32> {
            if offset == COMMON_DEVICE_FEATURE {
                return Ok((self.device_features >> (self.device_feature_page * 32)) as u32);
            }
            let start = offset as usize;
            let bytes = self
                .bytes
                .get(start..start + 4)
                .ok_or(VirtioError::AccessFailed)?;
            Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }

        fn write_u8(&mut self, _bar: u8, offset: u32, value: u8) -> VirtioResult<()> {
            if offset == COMMON_DEVICE_STATUS && self.reject_features {
                self.bytes[offset as usize] = value & !DeviceStatus::FEATURES_OK.bits();
            } else {
                self.bytes[offset as usize] = value;
            }
            Ok(())
        }

        fn write_u32(&mut self, _bar: u8, offset: u32, value: u32) -> VirtioResult<()> {
            match offset {
                COMMON_DEVICE_FEATURE_SELECT => self.device_feature_page = value,
                COMMON_DRIVER_FEATURE_SELECT => self.driver_feature_page = value,
                COMMON_DRIVER_FEATURE => {
                    let shift = self.driver_feature_page * 32;
                    let mask = u64::from(u32::MAX) << shift;
                    self.driver_features =
                        (self.driver_features & !mask) | (u64::from(value) << shift);
                }
                _ => {
                    let start = offset as usize;
                    let bytes = self
                        .bytes
                        .get_mut(start..start + 4)
                        .ok_or(VirtioError::AccessFailed)?;
                    bytes.copy_from_slice(&value.to_le_bytes());
                }
            }
            Ok(())
        }
    }

    #[test]
    fn parses_virtio_pci_capabilities() {
        let (config, bars) = valid_capabilities();
        let parsed = VirtioPciCapabilities::parse(&config, &bars).unwrap();
        assert_eq!(parsed.common.offset, 0);
        assert_eq!(parsed.notify.offset, 0x100);
        assert_eq!(parsed.notify_off_multiplier, 4);
        assert_eq!(parsed.isr.offset, 0x200);
        assert_eq!(parsed.device.map(|region| region.offset), Some(0x300));
    }

    #[test]
    fn rejects_capability_outside_bar() {
        let (config, mut bars) = valid_capabilities();
        bars[0].size = 0x350;
        assert_eq!(
            VirtioPciCapabilities::parse(&config, &bars),
            Err(VirtioError::RegionOverflow)
        );
    }

    #[test]
    fn rejects_capability_offset_overflow() {
        let (mut config, bars) = valid_capabilities();
        config.write_u32(0x48, u32::MAX).unwrap();
        config.write_u32(0x4c, 2).unwrap();
        assert_eq!(
            VirtioPciCapabilities::parse(&config, &bars),
            Err(VirtioError::RegionOverflow)
        );
    }

    #[test]
    fn rejects_capability_loop() {
        let (mut config, bars) = valid_capabilities();
        config.write_u8(0x79, 0x40).unwrap();
        assert_eq!(
            VirtioPciCapabilities::parse(&config, &bars),
            Err(VirtioError::CapabilityLoop)
        );
    }

    #[test]
    fn negotiates_features_and_reaches_driver_ok() {
        let (config, bars) = valid_capabilities();
        let capabilities = VirtioPciCapabilities::parse(&config, &bars).unwrap();
        let access = MockAccess::new(VIRTIO_F_VERSION_1 | 5);
        let transport = VirtioPciTransport::new(capabilities, access);
        let mut device = VirtioDevice::new(transport);
        device.begin_initialization().unwrap();
        let selected = device
            .negotiate_features(
                FeatureSet::new(VIRTIO_F_VERSION_1 | 1),
                FeatureSet::new(VIRTIO_F_VERSION_1),
            )
            .unwrap();
        device.finish_initialization().unwrap();
        assert_eq!(selected.bits(), VIRTIO_F_VERSION_1 | 1);
        assert_eq!(device.transport().access().driver_features, selected.bits());
        let status = device.transport_mut().read_status().unwrap();
        assert!(status.contains(DeviceStatus::ACKNOWLEDGE));
        assert!(status.contains(DeviceStatus::DRIVER));
        assert!(status.contains(DeviceStatus::FEATURES_OK));
        assert!(status.contains(DeviceStatus::DRIVER_OK));
    }

    #[test]
    fn rejects_missing_required_feature() {
        let (config, bars) = valid_capabilities();
        let capabilities = VirtioPciCapabilities::parse(&config, &bars).unwrap();
        let transport = VirtioPciTransport::new(capabilities, MockAccess::new(0));
        let mut device = VirtioDevice::new(transport);
        device.begin_initialization().unwrap();
        assert_eq!(
            device.negotiate_features(
                FeatureSet::new(VIRTIO_F_VERSION_1),
                FeatureSet::new(VIRTIO_F_VERSION_1),
            ),
            Err(VirtioError::RequiredFeatureMissing)
        );
        assert!(
            device
                .transport_mut()
                .read_status()
                .unwrap()
                .contains(DeviceStatus::FAILED)
        );
    }

    #[test]
    fn rejects_features_ok_clear_by_device() {
        let (config, bars) = valid_capabilities();
        let capabilities = VirtioPciCapabilities::parse(&config, &bars).unwrap();
        let mut access = MockAccess::new(VIRTIO_F_VERSION_1);
        access.reject_features = true;
        let transport = VirtioPciTransport::new(capabilities, access);
        let mut device = VirtioDevice::new(transport);
        device.begin_initialization().unwrap();
        assert_eq!(
            device.negotiate_features(
                FeatureSet::new(VIRTIO_F_VERSION_1),
                FeatureSet::new(VIRTIO_F_VERSION_1),
            ),
            Err(VirtioError::FeaturesRejected)
        );
    }
}
