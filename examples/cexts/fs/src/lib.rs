#![no_std]

#[repr(C)]
pub struct FsStub {
    pub version: u16,
    pub reserved: u16,
}

#[unsafe(no_mangle)]
pub extern "C" fn mochi_module_init() -> *const FsStub {
    core::ptr::null()
}
