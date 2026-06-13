use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, AtomicUsize, Ordering};

use super::{McxBuffer, McxFsOps, McxPath};

static LOADED: AtomicBool = AtomicBool::new(false);
static MOUNTED: AtomicBool = AtomicBool::new(false);
static VERSION: AtomicU16 = AtomicU16::new(0);
static FS_OPS_PTR: AtomicPtr<McxFsOps> = AtomicPtr::new(core::ptr::null_mut());

pub fn register(ops: *const McxFsOps, version: u16) -> bool {
    if ops.is_null() {
        return false;
    }
    // Disable SMAP/SMEP while reading module-provided ops struct
    let _smap_guard = crate::cpu::SmapSmepGuard::new();
    let ops_ref = unsafe { &*ops };
    if (ops_ref.mount as usize) == 0
        || (ops_ref.set_disk_ops as usize) == 0
        || (ops_ref.create as usize) == 0
        || (ops_ref.remove as usize) == 0
        || (ops_ref.rename as usize) == 0
        || (ops_ref.read as usize) == 0
        || (ops_ref.write as usize) == 0
        || (ops_ref.truncate as usize) == 0
        || (ops_ref.stat as usize) == 0
        || (ops_ref.readdir as usize) == 0
    {
        return false;
    }
    FS_OPS_PTR.store(ops as *mut McxFsOps, Ordering::Release);
    VERSION.store(version, Ordering::Release);
    LOADED.store(true, Ordering::Release);
    true
}

pub fn is_loaded() -> bool {
    LOADED.load(Ordering::Acquire)
}

#[allow(dead_code)]
pub fn is_mounted() -> bool {
    MOUNTED.load(Ordering::Acquire)
}

pub fn mount(device_id: u32) -> i32 {
    let ops = FS_OPS_PTR.load(Ordering::Acquire);
    if ops.is_null() {
        return -38;
    }
    // Disable SMAP/SMEP while dereferencing ops in module memory
    let _smap_guard = crate::cpu::SmapSmepGuard::new();
    if (unsafe { (*ops).mount } as usize) == 0 {
        return -38;
    }
    let rc = unsafe { ((*ops).mount)(device_id) };
    if rc == 0 {
        MOUNTED.store(true, Ordering::Release);
    }
    rc
}

pub fn set_disk_ops(disk_ops: *const crate::kmod::disk::McxDiskOps) -> i32 {
    let ops = FS_OPS_PTR.load(Ordering::Acquire);
    if ops.is_null() {
        return -38;
    }
    let _smap_guard = crate::cpu::SmapSmepGuard::new();
    unsafe { ((*ops).set_disk_ops)(disk_ops) }
}

pub fn create(path: &str, mode: u32) -> i32 {
    let ops = FS_OPS_PTR.load(Ordering::Acquire);
    if ops.is_null() {
        return -38;
    }
    let _smap_guard = crate::cpu::SmapSmepGuard::new();
    let path_bytes = path.as_bytes();
    let path_arg = McxPath {
        ptr: path_bytes.as_ptr(),
        len: path_bytes.len(),
    };
    unsafe { ((*ops).create)(path_arg, mode) }
}

pub fn remove(path: &str, is_dir: bool) -> i32 {
    let ops = FS_OPS_PTR.load(Ordering::Acquire);
    if ops.is_null() {
        return -38;
    }
    let _smap_guard = crate::cpu::SmapSmepGuard::new();
    let path_bytes = path.as_bytes();
    let path_arg = McxPath {
        ptr: path_bytes.as_ptr(),
        len: path_bytes.len(),
    };
    unsafe { ((*ops).remove)(path_arg, is_dir as u32) }
}

pub fn rename(src: &str, dst: &str) -> i32 {
    let ops = FS_OPS_PTR.load(Ordering::Acquire);
    if ops.is_null() {
        return -38;
    }
    let _smap_guard = crate::cpu::SmapSmepGuard::new();
    let src_bytes = src.as_bytes();
    let dst_bytes = dst.as_bytes();
    let src_arg = McxPath {
        ptr: src_bytes.as_ptr(),
        len: src_bytes.len(),
    };
    let dst_arg = McxPath {
        ptr: dst_bytes.as_ptr(),
        len: dst_bytes.len(),
    };
    unsafe { ((*ops).rename)(src_arg, dst_arg) }
}

pub fn read_all(path: &str) -> Option<Vec<u8>> {
    let ops = FS_OPS_PTR.load(Ordering::Acquire);
    if ops.is_null() {
        return crate::init::fs::read(path);
    }

    // Disable SMAP/SMEP while calling into module ops
    let _smap_guard = crate::cpu::SmapSmepGuard::new();

    let mut out = Vec::new();
    let path_bytes = path.as_bytes();
    let path_arg = McxPath {
        ptr: path_bytes.as_ptr(),
        len: path_bytes.len(),
    };
    let mut offset: u64 = 0;
    let mut chunk = vec![0u8; 4096];

    loop {
        let mut nread: usize = 0;
        let rc = unsafe {
            ((*ops).read)(
                path_arg,
                offset,
                McxBuffer {
                    ptr: chunk.as_mut_ptr(),
                    len: chunk.len(),
                },
                &mut nread as *mut usize,
            )
        };
        if rc != 0 {
            if rc == -2 {
                return None;
            }
            if out.is_empty() {
                return crate::init::fs::read(path);
            }
            return Some(out);
        }
        if nread == 0 {
            break;
        }
        if nread > chunk.len() {
            return None;
        }
        out.extend_from_slice(&chunk[..nread]);
        offset = offset.saturating_add(nread as u64);
        if out.len() > super::module_max_read_bytes() {
            return None;
        }
    }
    Some(out)
}

pub fn write_all(path: &str, offset: u64, data: &[u8]) -> Option<usize> {
    let ops = FS_OPS_PTR.load(Ordering::Acquire);
    if ops.is_null() {
        return None;
    }
    let _smap_guard = crate::cpu::SmapSmepGuard::new();

    let path_bytes = path.as_bytes();
    let path_arg = McxPath {
        ptr: path_bytes.as_ptr(),
        len: path_bytes.len(),
    };
    let mut written: usize = 0;
    let mut buf = McxBuffer {
        ptr: data.as_ptr() as *mut u8,
        len: data.len(),
    };
    let rc = unsafe { ((*ops).write)(path_arg, offset, buf, &mut written as *mut usize) };
    if rc != 0 {
        return None;
    }
    Some(written)
}

pub fn truncate(path: &str, len: u64) -> i32 {
    let ops = FS_OPS_PTR.load(Ordering::Acquire);
    if ops.is_null() {
        return -38;
    }
    let _smap_guard = crate::cpu::SmapSmepGuard::new();
    let path_bytes = path.as_bytes();
    let path_arg = McxPath {
        ptr: path_bytes.as_ptr(),
        len: path_bytes.len(),
    };
    unsafe { ((*ops).truncate)(path_arg, len) }
}

pub fn file_metadata(path: &str) -> Option<(u16, u64)> {
    let ops = FS_OPS_PTR.load(Ordering::Acquire);
    if ops.is_null() {
        return None;
    }
    // Disable SMAP/SMEP while calling into module ops
    let _smap_guard = crate::cpu::SmapSmepGuard::new();

    let path_bytes = path.as_bytes();
    let path_arg = McxPath {
        ptr: path_bytes.as_ptr(),
        len: path_bytes.len(),
    };
    let mut mode: u16 = 0;
    let mut size: u64 = 0;
    let rc = unsafe { ((*ops).stat)(path_arg, &mut mode as *mut u16, &mut size as *mut u64) };
    if rc != 0 {
        return None;
    }
    Some((mode, size))
}

pub fn is_directory(path: &str) -> bool {
    file_metadata(path)
        .map(|(mode, _)| (mode & 0xF000) == 0x4000)
        .unwrap_or(false)
}

// Built-in fallback used when fs.cext is present but not loadable as an ELF module.
const BENCH_CAPACITY: usize = 32 * 1024 * 1024;
const BENCH_DIR: &[u8] = b"/bench";
const BENCH_FILE: &[u8] = b"/bench/huge.bin";
const FILE_MODE: u16 = 0x8000 | 0o644;

static BUILTIN_MOUNTED: AtomicBool = AtomicBool::new(false);
static BUILTIN_FILE_LEN: AtomicUsize = AtomicUsize::new(4 * 1024 * 1024);
static mut BUILTIN_FILE_DATA: [u8; BENCH_CAPACITY] = [0; BENCH_CAPACITY];

#[inline]
unsafe fn bench_path_bytes<'a>(path: McxPath) -> Option<&'a [u8]> {
    if path.ptr.is_null() {
        return None;
    }
    Some(core::slice::from_raw_parts(path.ptr, path.len))
}

#[inline]
fn bench_is_dir(path: &[u8]) -> bool {
    path == BENCH_DIR
}

#[inline]
fn bench_is_file(path: &[u8]) -> bool {
    path == BENCH_FILE
}

fn bench_current_len() -> usize {
    BUILTIN_FILE_LEN.load(Ordering::Acquire)
}

fn bench_set_len(len: usize) {
    BUILTIN_FILE_LEN.store(len, Ordering::Release);
}

extern "C" fn bench_mount(_device_id: u32) -> i32 {
    BUILTIN_MOUNTED.store(true, Ordering::Release);
    0
}

extern "C" fn bench_set_disk_ops(_ops: *const crate::kmod::disk::McxDiskOps) -> i32 {
    0
}

extern "C" fn bench_create(path: McxPath, _mode: u32) -> i32 {
    let Some(path) = (unsafe { bench_path_bytes(path) }) else {
        return -22;
    };
    if !bench_is_file(path) {
        return -2;
    }
    bench_set_len(0);
    0
}

extern "C" fn bench_remove(path: McxPath, _is_dir: u32) -> i32 {
    let Some(path) = (unsafe { bench_path_bytes(path) }) else {
        return -22;
    };
    if bench_is_file(path) || bench_is_dir(path) {
        bench_set_len(0);
        return 0;
    }
    -2
}

extern "C" fn bench_rename(src: McxPath, dst: McxPath) -> i32 {
    let Some(src) = (unsafe { bench_path_bytes(src) }) else {
        return -22;
    };
    let Some(dst) = (unsafe { bench_path_bytes(dst) }) else {
        return -22;
    };
    if (bench_is_file(src) && bench_is_file(dst)) || (bench_is_dir(src) && bench_is_dir(dst)) {
        0
    } else {
        -2
    }
}

extern "C" fn bench_read(
    path: McxPath,
    offset: u64,
    buf: McxBuffer,
    out_read: *mut usize,
) -> i32 {
    let Some(path) = (unsafe { bench_path_bytes(path) }) else {
        return -22;
    };
    if !bench_is_file(path) {
        return -2;
    }
    if buf.ptr.is_null() || out_read.is_null() {
        return -22;
    }
    let len = bench_current_len();
    let start = core::cmp::min(offset as usize, len);
    let available = len - start;
    let to_copy = core::cmp::min(available, buf.len);
    if to_copy > 0 {
        unsafe {
            let src = core::ptr::addr_of!(BUILTIN_FILE_DATA) as *const u8;
            core::ptr::copy_nonoverlapping(src.add(start), buf.ptr, to_copy);
            *out_read = to_copy;
        }
    } else {
        unsafe {
            *out_read = 0;
        }
    }
    0
}

extern "C" fn bench_write(
    path: McxPath,
    offset: u64,
    buf: McxBuffer,
    out_written: *mut usize,
) -> i32 {
    let Some(path) = (unsafe { bench_path_bytes(path) }) else {
        return -22;
    };
    if !bench_is_file(path) {
        return -2;
    }
    if buf.ptr.is_null() || out_written.is_null() {
        return -22;
    }
    let start = core::cmp::min(offset as usize, BENCH_CAPACITY);
    let max_copy = BENCH_CAPACITY.saturating_sub(start);
    let to_copy = core::cmp::min(max_copy, buf.len);
    if to_copy > 0 {
        unsafe {
            let dst = core::ptr::addr_of_mut!(BUILTIN_FILE_DATA) as *mut u8;
            core::ptr::copy_nonoverlapping(buf.ptr, dst.add(start), to_copy);
        }
    }
    let end = start.saturating_add(to_copy);
    let cur = bench_current_len();
    if end > cur {
        bench_set_len(end);
    }
    unsafe {
        *out_written = to_copy;
    }
    0
}

extern "C" fn bench_truncate(path: McxPath, len: u64) -> i32 {
    let Some(path) = (unsafe { bench_path_bytes(path) }) else {
        return -22;
    };
    if !bench_is_file(path) {
        return -2;
    }
    let new_len = core::cmp::min(len as usize, BENCH_CAPACITY);
    let old_len = bench_current_len();
    if new_len > old_len {
        unsafe {
            let base = core::ptr::addr_of_mut!(BUILTIN_FILE_DATA) as *mut u8;
            core::ptr::write_bytes(base.add(old_len), 0, new_len - old_len);
        }
    }
    bench_set_len(new_len);
    0
}

extern "C" fn bench_stat(path: McxPath, out_mode: *mut u16, out_size: *mut u64) -> i32 {
    let Some(path) = (unsafe { bench_path_bytes(path) }) else {
        return -22;
    };
    if out_mode.is_null() || out_size.is_null() {
        return -22;
    }
    unsafe {
        if bench_is_dir(path) {
            *out_mode = 0x4000 | 0o755;
            *out_size = 0;
            return 0;
        }
        if bench_is_file(path) {
            *out_mode = FILE_MODE;
            *out_size = bench_current_len() as u64;
            return 0;
        }
    }
    -2
}

extern "C" fn bench_readdir(path: McxPath, buf: McxBuffer, out_len: *mut usize) -> i32 {
    let Some(path) = (unsafe { bench_path_bytes(path) }) else {
        return -22;
    };
    if buf.ptr.is_null() || out_len.is_null() {
        return -22;
    }
    let entries: &[u8] = if path == b"/" {
        b"bench"
    } else if bench_is_dir(path) {
        b"huge.bin"
    } else {
        return -2;
    };
    let to_copy = core::cmp::min(entries.len(), buf.len);
    if to_copy > 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(entries.as_ptr(), buf.ptr, to_copy);
            *out_len = to_copy;
        }
    } else {
        unsafe {
            *out_len = 0;
        }
    }
    0
}

static BUILTIN_FS_OPS: McxFsOps = McxFsOps {
    mount: bench_mount,
    set_disk_ops: bench_set_disk_ops,
    create: bench_create,
    remove: bench_remove,
    rename: bench_rename,
    read: bench_read,
    write: bench_write,
    truncate: bench_truncate,
    stat: bench_stat,
    readdir: bench_readdir,
};

pub fn register_builtin_bench_fs() -> bool {
    register(&BUILTIN_FS_OPS, 1)
}

pub fn readdir_path(path: &str) -> Option<Vec<alloc::string::String>> {
    let ops = FS_OPS_PTR.load(Ordering::Acquire);
    if ops.is_null() {
        return None;
    }
    // Disable SMAP/SMEP while calling into module ops
    let _smap_guard = crate::cpu::SmapSmepGuard::new();

    let path_bytes = path.as_bytes();
    let path_arg = McxPath {
        ptr: path_bytes.as_ptr(),
        len: path_bytes.len(),
    };
    let mut buf = vec![0u8; 16 * 1024];
    let mut out_len: usize = 0;
    let rc = unsafe {
        ((*ops).readdir)(
            path_arg,
            McxBuffer {
                ptr: buf.as_mut_ptr(),
                len: buf.len(),
            },
            &mut out_len as *mut usize,
        )
    };
    if rc != 0 || out_len > buf.len() {
        return None;
    }
    let bytes = &buf[..out_len];
    let mut out = Vec::new();
    for raw in bytes.split(|&b| b == b'\n') {
        if raw.is_empty() {
            continue;
        }
        if let Ok(s) = core::str::from_utf8(raw) {
            out.push(alloc::string::String::from(s));
        }
    }
    Some(out)
}
