use super::error::{VirtioError, VirtioResult};
use super::feature::FeatureSet;
use super::transport::{PciTransportAccess, VirtioPciTransport};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceStatus(u8);

impl DeviceStatus {
    pub const ACKNOWLEDGE: Self = Self(1);
    pub const DRIVER: Self = Self(2);
    pub const DRIVER_OK: Self = Self(4);
    pub const FEATURES_OK: Self = Self(8);
    pub const DEVICE_NEEDS_RESET: Self = Self(64);
    pub const FAILED: Self = Self(128);

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

pub struct VirtioDevice<A> {
    transport: VirtioPciTransport<A>,
    negotiated_features: FeatureSet,
}

impl<A: PciTransportAccess> VirtioDevice<A> {
    pub fn new(transport: VirtioPciTransport<A>) -> Self {
        Self {
            transport,
            negotiated_features: FeatureSet::default(),
        }
    }

    pub fn transport(&self) -> &VirtioPciTransport<A> {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut VirtioPciTransport<A> {
        &mut self.transport
    }

    pub const fn negotiated_features(&self) -> FeatureSet {
        self.negotiated_features
    }

    pub fn reset(&mut self) -> VirtioResult<()> {
        self.transport.write_status(DeviceStatus::default())?;
        if self.transport.read_status()?.bits() != 0 {
            return Err(VirtioError::DeviceResetFailed);
        }
        self.negotiated_features = FeatureSet::default();
        Ok(())
    }

    pub fn begin_initialization(&mut self) -> VirtioResult<()> {
        self.reset()?;
        self.transport
            .write_status(DeviceStatus::ACKNOWLEDGE.union(DeviceStatus::DRIVER))
    }

    pub fn negotiate_features(
        &mut self,
        requested: FeatureSet,
        required: FeatureSet,
    ) -> VirtioResult<FeatureSet> {
        let supported = self.transport.read_device_features()?;
        if !supported.contains_all(required) {
            self.fail();
            return Err(VirtioError::RequiredFeatureMissing);
        }
        let selected = supported.intersection(requested).union(required);
        self.transport.write_driver_features(selected)?;
        let status = self
            .transport
            .read_status()?
            .union(DeviceStatus::FEATURES_OK);
        self.transport.write_status(status)?;
        if !self
            .transport
            .read_status()?
            .contains(DeviceStatus::FEATURES_OK)
        {
            self.fail();
            return Err(VirtioError::FeaturesRejected);
        }
        self.negotiated_features = selected;
        Ok(selected)
    }

    pub fn finish_initialization(&mut self) -> VirtioResult<()> {
        let status = self.transport.read_status()?.union(DeviceStatus::DRIVER_OK);
        self.transport.write_status(status)
    }

    pub fn fail(&mut self) {
        if let Ok(status) = self.transport.read_status() {
            let _ = self
                .transport
                .write_status(status.union(DeviceStatus::FAILED));
        }
    }
}
