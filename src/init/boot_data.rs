//! Borrow the boot-selected module as immutable bytes. Filesystem formats and
//! paths are interpreted by resource consumers outside the kernel.
use mnu_abi::status::Error;

static MODULE: spin::Once<&'static [u8]> = spin::Once::new();

/// Install the boot chain's retained range before starting user processes.
/// Repeating the same range is idempotent; a different range cannot replace it.
///
/// # Safety
/// The supplied nonempty range must be mapped, initialized, immutable and kept
/// resident for the kernel's lifetime. Boot-memory preparation owns that pin.
pub(crate) unsafe fn install(address: u64, length: usize) -> Result<(), Error> {
    if address == 0
        || length == 0
        || length > isize::MAX as usize
        || address.checked_add(length as u64).is_none()
    {
        return Err(Error::InvalidArgument);
    }
    let bytes = unsafe { core::slice::from_raw_parts(address as *const u8, length) };
    let installed = MODULE.call_once(|| bytes);
    if core::ptr::eq(*installed, bytes) {
        Ok(())
    } else {
        Err(Error::AlreadyExists)
    }
}

pub(crate) fn boot_module_bytes() -> &'static [u8] {
    MODULE.get().copied().unwrap_or(&[])
}

/// Opaque data selected for the platform backend. No path lookup or format
/// interpretation takes place here, including when the selected range is empty.
pub fn platform_data() -> Option<&'static [u8]> {
    mnu_abi::boot_module::decode(boot_module_bytes())
        .ok()
        .map(|module| module.platform_data)
}
