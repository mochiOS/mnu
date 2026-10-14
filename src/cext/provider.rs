use alloc::string::String;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CextKind {
    BlockDevice,
    DeviceService,
    Other,
}

/// Only interfaces with a kernel-owned adapter may execute in kernel space.
/// Unknown or mixed interfaces cannot be cast to a block-provider ABI.
pub(super) fn provider_kind(interfaces: &[String]) -> Option<CextKind> {
    if !interfaces.is_empty()
        && interfaces
            .iter()
            .all(|interface| interface == "block.device")
    {
        Some(CextKind::BlockDevice)
    } else {
        None
    }
}
