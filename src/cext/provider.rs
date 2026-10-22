#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CextKind {
    BlockDevice,
    DeviceService,
    Other,
}

/// Only a numeric boot-selected adapter may execute kernel extension code.
pub(super) fn provider_kind(adapter: u32) -> Option<CextKind> {
    match adapter {
        mnu_abi::boot_extensions::ADAPTER_BLOCK => Some(CextKind::BlockDevice),
        _ => None,
    }
}
