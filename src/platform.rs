//! Optional platform integration supplied by the system using mnu.
//!
//! The kernel owns the syscall and capability checks. Device discovery,
//! transport protocols, and product policy stay behind this interface.

use crate::interrupt::spinlock::SpinLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformError {
    Unsupported,
    Unavailable,
    InvalidRequest,
    Transport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayInfo {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub red_offset: u8,
    pub green_offset: u8,
    pub blue_offset: u8,
    pub surface_address: u64,
    pub surface_size: u64,
    pub shared_surface: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceControlResponse {
    pub status: u32,
    pub device_id: u32,
    pub values: [u64; 4],
}

pub struct PlatformOps {
    pub display_info: fn() -> Result<DisplayInfo, PlatformError>,
    pub display_transfer_limit: fn() -> Result<usize, PlatformError>,
    pub present_display:
        fn(x: u32, y: u32, width: u32, height: u32, pixels: &[u8]) -> Result<(), PlatformError>,
    pub commit_display: fn(x: u32, y: u32, width: u32, height: u32) -> Result<(), PlatformError>,
    pub device_control: fn(
        operation: u16,
        device_id: u32,
        arguments: [u64; 4],
    ) -> Result<DeviceControlResponse, PlatformError>,
}

static PLATFORM_OPS: SpinLock<Option<&'static PlatformOps>> = SpinLock::new(None);

pub fn install(ops: &'static PlatformOps) -> Result<(), PlatformError> {
    let mut slot = PLATFORM_OPS.lock();
    if slot.is_some() {
        return Err(PlatformError::InvalidRequest);
    }
    *slot = Some(ops);
    Ok(())
}

fn with_ops<T>(
    f: impl FnOnce(&PlatformOps) -> Result<T, PlatformError>,
) -> Result<T, PlatformError> {
    let ops = *PLATFORM_OPS.lock();
    f(ops.ok_or(PlatformError::Unsupported)?)
}

pub fn display_info() -> Result<DisplayInfo, PlatformError> {
    with_ops(|ops| (ops.display_info)())
}

pub fn display_transfer_limit() -> Result<usize, PlatformError> {
    with_ops(|ops| (ops.display_transfer_limit)())
}

pub fn present_display(
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    pixels: &[u8],
) -> Result<(), PlatformError> {
    with_ops(|ops| (ops.present_display)(x, y, width, height, pixels))
}

pub fn commit_display(x: u32, y: u32, width: u32, height: u32) -> Result<(), PlatformError> {
    with_ops(|ops| (ops.commit_display)(x, y, width, height))
}

pub fn device_control(
    operation: u16,
    device_id: u32,
    arguments: [u64; 4],
) -> Result<DeviceControlResponse, PlatformError> {
    with_ops(|ops| (ops.device_control)(operation, device_id, arguments))
}
