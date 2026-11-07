//! Firmware framebuffer metadata for device discovery and mapping.

use spin::Once;

static FB_INFO: Once<FramebufferInfo> = Once::new();

#[derive(Clone, Copy)]
pub struct FramebufferInfo {
    pub addr: u64,
    pub size: usize,
    pub width: usize,
    pub height: usize,
    pub stride: usize,
}

pub fn get_info() -> Option<FramebufferInfo> {
    FB_INFO.get().copied()
}

/// Register the firmware framebuffer without writing to its pixels.
pub fn init(addr: u64, size: usize, width: usize, height: usize, stride: usize) {
    let required = stride
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(4));
    if addr == 0
        || width == 0
        || height == 0
        || stride < width
        || required.is_none_or(|bytes| bytes > size)
        || addr.checked_add(size as u64).is_none()
    {
        return;
    }
    FB_INFO.call_once(|| FramebufferInfo {
        addr,
        size,
        width,
        height,
        stride,
    });
}
