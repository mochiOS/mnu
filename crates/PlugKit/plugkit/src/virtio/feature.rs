#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeatureSet(u64);

pub const VIRTIO_F_VERSION_1: u64 = 1u64 << 32;

impl FeatureSet {
    pub const fn new(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn contains_all(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl From<u64> for FeatureSet {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}
