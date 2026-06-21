use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, Ordering};

#[repr(C)]
pub struct McxDiskOps {
    pub probe: extern "C" fn() -> i32,
    pub read_sector: extern "C" fn(disk_id: u32, lba: u64, buf: *mut u8, buf_len: usize) -> i32,
    pub write_sector: extern "C" fn(disk_id: u32, lba: u64, buf: *const u8, buf_len: usize) -> i32,
}

static LOADED: AtomicBool = AtomicBool::new(false);
static VERSION: AtomicU16 = AtomicU16::new(0);
static OPS: AtomicPtr<McxDiskOps> = AtomicPtr::new(core::ptr::null_mut());

pub fn activate_bundle(version: u16, ops: *const McxDiskOps) -> bool {
    if ops.is_null() {
        return false;
    }
    VERSION.store(version, Ordering::Release);
    OPS.store(ops.cast_mut(), Ordering::Release);
    LOADED.store(true, Ordering::Release);
    true
}

pub fn ops_ptr() -> *const McxDiskOps {
    OPS.load(Ordering::Acquire)
}

pub fn is_loaded() -> bool {
    LOADED.load(Ordering::Acquire) && !ops_ptr().is_null()
}

#[allow(dead_code)]
pub fn version() -> u16 {
    VERSION.load(Ordering::Acquire)
}

#[allow(dead_code)]
pub fn probe() -> i32 {
    let ops = ops_ptr();
    if ops.is_null() {
        return -38;
    }
    unsafe { ((*ops).probe)() }
}

#[allow(dead_code)]
pub fn read_sector(disk_id: u32, lba: u64, buf: &mut [u8]) -> i32 {
    let ops = ops_ptr();
    if ops.is_null() {
        return -38;
    }
    unsafe { ((*ops).read_sector)(disk_id, lba, buf.as_mut_ptr(), buf.len()) }
}

#[allow(dead_code)]
pub fn write_sector(disk_id: u32, lba: u64, buf: &[u8]) -> i32 {
    let ops = ops_ptr();
    if ops.is_null() {
        return -38;
    }
    unsafe { ((*ops).write_sector)(disk_id, lba, buf.as_ptr(), buf.len()) }
}
