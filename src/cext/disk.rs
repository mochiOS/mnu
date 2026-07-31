use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, Ordering};

use crate::interrupt::spinlock::SpinLock;

#[repr(C)]
pub struct McxDiskOps {
    pub probe: extern "C" fn() -> i32,
    pub read_sector: extern "C" fn(disk_id: u32, lba: u64, buf: *mut u8, buf_len: usize) -> i32,
    pub write_sector: extern "C" fn(disk_id: u32, lba: u64, buf: *const u8, buf_len: usize) -> i32,
    pub flush: extern "C" fn(disk_id: u32) -> i32,
}

static LOADED: AtomicBool = AtomicBool::new(false);
static VERSION: AtomicU16 = AtomicU16::new(0);
static OPS: AtomicPtr<McxDiskOps> = AtomicPtr::new(core::ptr::null_mut());
static DISK_IO_LOCK: SpinLock<()> = SpinLock::new(());

extern "C" fn serialized_probe() -> i32 {
    let ops = ops_ptr();
    if ops.is_null() {
        return -38;
    }
    let _guard = DISK_IO_LOCK.lock();
    unsafe { ((*ops).probe)() }
}

extern "C" fn serialized_read_sector(disk_id: u32, lba: u64, buf: *mut u8, buf_len: usize) -> i32 {
    let ops = ops_ptr();
    if ops.is_null() {
        return -38;
    }
    let _guard = DISK_IO_LOCK.lock();
    unsafe { ((*ops).read_sector)(disk_id, lba, buf, buf_len) }
}

extern "C" fn serialized_write_sector(
    disk_id: u32,
    lba: u64,
    buf: *const u8,
    buf_len: usize,
) -> i32 {
    let ops = ops_ptr();
    if ops.is_null() {
        return -38;
    }
    let _guard = DISK_IO_LOCK.lock();
    unsafe { ((*ops).write_sector)(disk_id, lba, buf, buf_len) }
}

extern "C" fn serialized_flush(disk_id: u32) -> i32 {
    let ops = ops_ptr();
    if ops.is_null() {
        return -38;
    }
    let _guard = DISK_IO_LOCK.lock();
    unsafe { ((*ops).flush)(disk_id) }
}

static SERIALIZED_OPS: McxDiskOps = McxDiskOps {
    probe: serialized_probe,
    read_sector: serialized_read_sector,
    write_sector: serialized_write_sector,
    flush: serialized_flush,
};

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

pub fn serialized_ops_ptr() -> *const McxDiskOps {
    &SERIALIZED_OPS
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
    serialized_probe()
}

#[allow(dead_code)]
pub fn read_sector(disk_id: u32, lba: u64, buf: &mut [u8]) -> i32 {
    serialized_read_sector(disk_id, lba, buf.as_mut_ptr(), buf.len())
}

#[allow(dead_code)]
pub fn write_sector(disk_id: u32, lba: u64, buf: &[u8]) -> i32 {
    serialized_write_sector(disk_id, lba, buf.as_ptr(), buf.len())
}

#[allow(dead_code)]
pub fn flush(disk_id: u32) -> i32 {
    serialized_flush(disk_id)
}
