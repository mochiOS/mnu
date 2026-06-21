use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

#[repr(C)]
pub struct McxDiskOps {
    pub probe: extern "C" fn() -> i32,
    pub read_sector: extern "C" fn(disk_id: u32, lba: u64, buf: *mut u8, buf_len: usize) -> i32,
    pub write_sector: extern "C" fn(disk_id: u32, lba: u64, buf: *const u8, buf_len: usize) -> i32,
}

const ROOTFS_DISK_ID: u32 = 0;
const SECTOR_SIZE: usize = 512;

static LOADED: AtomicBool = AtomicBool::new(false);
static VERSION: AtomicU16 = AtomicU16::new(0);

extern "C" fn probe_impl() -> i32 {
    if crate::init::fs::rootfs_bytes().is_some() {
        1
    } else {
        -2
    }
}

extern "C" fn read_sector_impl(disk_id: u32, lba: u64, buf: *mut u8, buf_len: usize) -> i32 {
    if disk_id != ROOTFS_DISK_ID || buf.is_null() || buf_len == 0 || buf_len % SECTOR_SIZE != 0 {
        return -22;
    }
    let Some(rootfs) = crate::init::fs::rootfs_bytes() else {
        return -2;
    };
    let start = match (lba as usize).checked_mul(SECTOR_SIZE) {
        Some(v) => v,
        None => return -22,
    };
    let end = match start.checked_add(buf_len) {
        Some(v) => v,
        None => return -22,
    };
    if end > rootfs.len() {
        return -5;
    }
    unsafe {
        // Safety: caller provided a writable buffer of buf_len bytes and we checked bounds
        // against the immutable rootfs image before copying.
        core::ptr::copy_nonoverlapping(rootfs.as_ptr().add(start), buf, buf_len);
    }
    0
}

extern "C" fn write_sector_impl(
    disk_id: u32,
    _lba: u64,
    buf: *const u8,
    buf_len: usize,
) -> i32 {
    if disk_id != ROOTFS_DISK_ID || buf.is_null() || buf_len == 0 || buf_len % SECTOR_SIZE != 0 {
        return -22;
    }
    -30
}

static HOST_DISK_OPS: McxDiskOps = McxDiskOps {
    probe: probe_impl,
    read_sector: read_sector_impl,
    write_sector: write_sector_impl,
};

pub fn activate_bundle(version: u16) -> bool {
    if crate::init::fs::rootfs_bytes().is_none() {
        return false;
    }
    VERSION.store(version, Ordering::Release);
    LOADED.store(true, Ordering::Release);
    true
}

pub fn ops_ptr() -> *const McxDiskOps {
    if is_loaded() {
        &HOST_DISK_OPS as *const McxDiskOps
    } else {
        core::ptr::null()
    }
}

pub fn is_loaded() -> bool {
    LOADED.load(Ordering::Acquire)
}

#[allow(dead_code)]
pub fn version() -> u16 {
    VERSION.load(Ordering::Acquire)
}

#[allow(dead_code)]
pub fn probe() -> i32 {
    if !is_loaded() {
        return -38;
    }
    (HOST_DISK_OPS.probe)()
}

#[allow(dead_code)]
pub fn read_sector(disk_id: u32, lba: u64, buf: &mut [u8]) -> i32 {
    if !is_loaded() {
        return -38;
    }
    (HOST_DISK_OPS.read_sector)(disk_id, lba, buf.as_mut_ptr(), buf.len())
}

#[allow(dead_code)]
pub fn write_sector(disk_id: u32, lba: u64, buf: &[u8]) -> i32 {
    if !is_loaded() {
        return -38;
    }
    (HOST_DISK_OPS.write_sector)(disk_id, lba, buf.as_ptr(), buf.len())
}
