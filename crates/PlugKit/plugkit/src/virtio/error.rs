use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioError {
    InvalidPciCapabilityList,
    CapabilityLoop,
    MissingCommonConfiguration,
    MissingNotifyConfiguration,
    MissingIsrConfiguration,
    InvalidCapabilityLength,
    InvalidBar,
    BarIsIo,
    RegionOverflow,
    RegisterOutOfBounds,
    AccessFailed,
    DeviceResetFailed,
    RequiredFeatureMissing,
    FeaturesRejected,
    InvalidQueueSize,
    QueueUnavailable,
    QueueFull,
    InvalidDescriptor,
    InvalidUsedIndex,
    DmaBufferTooSmall,
    ArithmeticOverflow,
    CommandTimeout,
}

pub type VirtioResult<T> = Result<T, VirtioError>;

impl fmt::Display for VirtioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPciCapabilityList => "invalid PCI capability list",
            Self::CapabilityLoop => "PCI capability list contains a loop",
            Self::MissingCommonConfiguration => "virtio common configuration is missing",
            Self::MissingNotifyConfiguration => "virtio notify configuration is missing",
            Self::MissingIsrConfiguration => "virtio ISR configuration is missing",
            Self::InvalidCapabilityLength => "virtio PCI capability length is invalid",
            Self::InvalidBar => "virtio PCI capability references an invalid BAR",
            Self::BarIsIo => "virtio PCI capability references an I/O BAR",
            Self::RegionOverflow => "virtio PCI capability exceeds its BAR",
            Self::RegisterOutOfBounds => "virtio register access exceeds its capability",
            Self::AccessFailed => "virtio transport register access failed",
            Self::DeviceResetFailed => "virtio device did not reset",
            Self::RequiredFeatureMissing => "virtio device is missing a required feature",
            Self::FeaturesRejected => "virtio device rejected negotiated features",
            Self::InvalidQueueSize => "virtqueue size is invalid",
            Self::QueueUnavailable => "virtqueue is unavailable",
            Self::QueueFull => "virtqueue has no free descriptors",
            Self::InvalidDescriptor => "virtqueue descriptor is invalid",
            Self::InvalidUsedIndex => "virtqueue used ring index is invalid",
            Self::DmaBufferTooSmall => "virtqueue DMA buffer is too small",
            Self::ArithmeticOverflow => "virtio address calculation overflowed",
            Self::CommandTimeout => "virtio command timed out",
        })
    }
}
