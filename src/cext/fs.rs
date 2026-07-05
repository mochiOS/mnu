use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, Ordering};

use super::{McxBuffer, McxFsOps, McxPath};

static LOADED: AtomicBool = AtomicBool::new(false);
static VERSION: AtomicU16 = AtomicU16::new(0);
static OPS: AtomicPtr<McxFsOps> = AtomicPtr::new(core::ptr::null_mut());
static MOUNTED: AtomicBool = AtomicBool::new(false);

fn ops_ptr() -> *const McxFsOps {
    OPS.load(Ordering::Acquire)
}

fn debug_serial_write_str(s: &str) {
    use x86_64::instructions::port::Port;

    unsafe {
        let mut lsr = Port::<u8>::new(0x3FD);
        let mut data = Port::<u8>::new(0x3F8);
        for byte in s.bytes() {
            while (lsr.read() & 0x20) == 0 {}
            data.write(byte);
        }
    }
}

fn path_arg(path: &str) -> McxPath {
    McxPath {
        ptr: path.as_ptr(),
        len: path.len(),
    }
}

pub fn activate_bundle(version: u16, ops: *const McxFsOps) -> bool {
    if ops.is_null() {
        return false;
    }
    VERSION.store(version, Ordering::Release);
    OPS.store(ops.cast_mut(), Ordering::Release);
    LOADED.store(true, Ordering::Release);
    true
}

pub fn is_loaded() -> bool {
    LOADED.load(Ordering::Acquire) && !ops_ptr().is_null()
}

pub fn mount(device_id: u32) -> i32 {
    let ops = ops_ptr();
    if ops.is_null() {
        return -38;
    }
    let rc = unsafe { ((*ops).mount)(device_id) };
    if rc == 0 {
        MOUNTED.store(true, Ordering::Release);
    }
    rc
}

pub fn set_disk_ops(disk_ops: *const crate::cext::disk::McxDiskOps) -> i32 {
    let ops = ops_ptr();
    if ops.is_null() {
        return -38;
    }
    unsafe { ((*ops).set_disk_ops)(disk_ops) }
}

pub fn read_all(path: &str) -> Option<Vec<u8>> {
    let ops = ops_ptr();
    if ops.is_null() || !MOUNTED.load(Ordering::Acquire) {
        return None;
    }
    let (mode, size) = file_metadata(path)?;
    if (mode & 0xf000) == 0x4000 {
        return None;
    }
    let size = usize::try_from(size).ok()?;
    let mut data = vec![0u8; size];
    let mut read = 0usize;
    let rc = unsafe {
        ((*ops).read)(
            path_arg(path),
            0,
            McxBuffer {
                ptr: data.as_mut_ptr(),
                len: data.len(),
            },
            &mut read,
        )
    };
    if rc != 0 {
        return None;
    }
    if read != data.len() {
        return None;
    }
    data.truncate(read);
    Some(data)
}

pub fn write_all(path: &str, offset: u64, data: &[u8]) -> Option<usize> {
    let ops = ops_ptr();
    if ops.is_null() {
        return None;
    }
    let mut written = 0usize;
    let rc = unsafe {
        ((*ops).write)(
            path_arg(path),
            offset,
            McxBuffer {
                ptr: data.as_ptr() as *mut u8,
                len: data.len(),
            },
            &mut written,
        )
    };
    (rc == 0).then_some(written)
}

pub fn truncate(path: &str, len: u64) -> i32 {
    let ops = ops_ptr();
    if ops.is_null() {
        return -38;
    }
    unsafe { ((*ops).truncate)(path_arg(path), len) }
}

pub fn file_metadata(path: &str) -> Option<(u16, u64)> {
    if path == "/drivers/usb" {
        debug_serial_write_str("cext::fs::file_metadata /drivers/usb\n");
    }
    let ops = ops_ptr();
    if ops.is_null() || !MOUNTED.load(Ordering::Acquire) {
        return None;
    }
    let mut mode = 0u16;
    let mut size = 0u64;
    let rc = unsafe { ((*ops).stat)(path_arg(path), &mut mode, &mut size) };
    (rc == 0).then_some((mode, size))
}

pub fn is_directory(path: &str) -> bool {
    file_metadata(path)
        .map(|(mode, _)| (mode & 0xf000) == 0x4000)
        .unwrap_or(false)
}

pub fn readdir_path(path: &str) -> Option<Vec<String>> {
    if path == "/drivers/usb" {
        debug_serial_write_str("cext::fs::readdir /drivers/usb\n");
    }
    let ops = ops_ptr();
    if ops.is_null() || !MOUNTED.load(Ordering::Acquire) {
        return None;
    }
    let mut raw = vec![0u8; 4096];
    let mut out_len = 0usize;
    let rc = unsafe {
        ((*ops).readdir)(
            path_arg(path),
            McxBuffer {
                ptr: raw.as_mut_ptr(),
                len: raw.len(),
            },
            &mut out_len,
        )
    };
    if rc != 0 {
        return None;
    }
    raw.truncate(out_len);
    let mut names = Vec::new();
    for entry in raw.split(|b| *b == 0) {
        if entry.is_empty() {
            continue;
        }
        if let Ok(name) = core::str::from_utf8(entry) {
            names.push(name.to_string());
        }
    }
    Some(names)
}

pub fn create(path: &str, mode: u32) -> i32 {
    let ops = ops_ptr();
    if ops.is_null() {
        return -38;
    }
    unsafe { ((*ops).create)(path_arg(path), mode) }
}

pub fn remove(path: &str, is_dir: bool) -> i32 {
    let ops = ops_ptr();
    if ops.is_null() {
        return -38;
    }
    unsafe { ((*ops).remove)(path_arg(path), if is_dir { 1 } else { 0 }) }
}

pub fn rename(src: &str, dst: &str) -> i32 {
    let ops = ops_ptr();
    if ops.is_null() {
        return -38;
    }
    unsafe { ((*ops).rename)(path_arg(src), path_arg(dst)) }
}
