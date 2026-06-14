#![no_std]
#![no_main]

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct McxBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct McxPath {
    pub ptr: *const u8,
    pub len: usize,
}

#[repr(C)]
pub struct McxDiskOps {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct McxFsOps {
    pub mount: extern "C" fn(device_id: u32) -> i32,
    pub set_disk_ops: extern "C" fn(ops: *const McxDiskOps) -> i32,
    pub create: extern "C" fn(path: McxPath, mode: u32) -> i32,
    pub remove: extern "C" fn(path: McxPath, is_dir: u32) -> i32,
    pub rename: extern "C" fn(src: McxPath, dst: McxPath) -> i32,
    pub read:
        extern "C" fn(path: McxPath, offset: u64, buf: McxBuffer, out_read: *mut usize) -> i32,
    pub write:
        extern "C" fn(path: McxPath, offset: u64, buf: McxBuffer, out_written: *mut usize) -> i32,
    pub truncate: extern "C" fn(path: McxPath, len: u64) -> i32,
    pub stat: extern "C" fn(path: McxPath, out_mode: *mut u16, out_size: *mut u64) -> i32,
    pub readdir: extern "C" fn(path: McxPath, buf: McxBuffer, out_len: *mut usize) -> i32,
}

const BENCH_CAPACITY: usize = 32 * 1024 * 1024;
const BENCH_DIR: &[u8] = b"/bench";
const BENCH_FILE: &[u8] = b"/bench/huge.bin";
const FILE_MODE: u16 = 0x8000 | 0o644;

static MOUNTED: AtomicBool = AtomicBool::new(false);
static FILE_LEN: AtomicUsize = AtomicUsize::new(BENCH_CAPACITY);
static mut FILE_DATA: [u8; BENCH_CAPACITY] = [0; BENCH_CAPACITY];

#[inline]
unsafe fn path_bytes<'a>(path: McxPath) -> Option<&'a [u8]> {
    if path.ptr.is_null() {
        return None;
    }
    Some(core::slice::from_raw_parts(path.ptr, path.len))
}

#[inline]
fn is_bench_dir(path: &[u8]) -> bool {
    path == BENCH_DIR
}

#[inline]
fn is_bench_file(path: &[u8]) -> bool {
    path == BENCH_FILE
}

fn clamp_len(len: u64) -> usize {
    core::cmp::min(len as usize, BENCH_CAPACITY)
}

fn current_len() -> usize {
    FILE_LEN.load(Ordering::Acquire)
}

fn set_len(len: usize) {
    FILE_LEN.store(len, Ordering::Release);
}

extern "C" fn mount(_device_id: u32) -> i32 {
    MOUNTED.store(true, Ordering::Release);
    0
}

extern "C" fn set_disk_ops(_ops: *const McxDiskOps) -> i32 {
    0
}

extern "C" fn create(path: McxPath, _mode: u32) -> i32 {
    let Some(path) = (unsafe { path_bytes(path) }) else {
        return -22;
    };
    if !is_bench_file(path) {
        return -2;
    }
    set_len(0);
    0
}

extern "C" fn remove(path: McxPath, _is_dir: u32) -> i32 {
    let Some(path) = (unsafe { path_bytes(path) }) else {
        return -22;
    };
    if is_bench_file(path) || is_bench_dir(path) {
        set_len(0);
        return 0;
    }
    -2
}

extern "C" fn rename(src: McxPath, dst: McxPath) -> i32 {
    let Some(src) = (unsafe { path_bytes(src) }) else {
        return -22;
    };
    let Some(dst) = (unsafe { path_bytes(dst) }) else {
        return -22;
    };
    if (is_bench_file(src) && is_bench_file(dst)) || (is_bench_dir(src) && is_bench_dir(dst)) {
        0
    } else {
        -2
    }
}

extern "C" fn read(path: McxPath, offset: u64, buf: McxBuffer, out_read: *mut usize) -> i32 {
    let Some(path) = (unsafe { path_bytes(path) }) else {
        return -22;
    };
    if !is_bench_file(path) {
        return -2;
    }
    if buf.ptr.is_null() || out_read.is_null() {
        return -22;
    }
    let len = current_len();
    let start = core::cmp::min(offset as usize, len);
    let available = len - start;
    let to_copy = core::cmp::min(available, buf.len);
    if to_copy > 0 {
        unsafe {
            let src = core::ptr::addr_of!(FILE_DATA) as *const u8;
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

extern "C" fn write(path: McxPath, offset: u64, buf: McxBuffer, out_written: *mut usize) -> i32 {
    let Some(path) = (unsafe { path_bytes(path) }) else {
        return -22;
    };
    if !is_bench_file(path) {
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
            let dst = core::ptr::addr_of_mut!(FILE_DATA) as *mut u8;
            core::ptr::copy_nonoverlapping(buf.ptr, dst.add(start), to_copy);
        }
    }
    let end = start.saturating_add(to_copy);
    let cur = current_len();
    if end > cur {
        set_len(end);
    }
    unsafe {
        *out_written = to_copy;
    }
    0
}

extern "C" fn truncate(path: McxPath, len: u64) -> i32 {
    let Some(path) = (unsafe { path_bytes(path) }) else {
        return -22;
    };
    if !is_bench_file(path) {
        return -2;
    }
    let new_len = clamp_len(len);
    let old_len = current_len();
    if new_len > old_len {
        unsafe {
            let base = core::ptr::addr_of_mut!(FILE_DATA) as *mut u8;
            core::ptr::write_bytes(base.add(old_len), 0, new_len - old_len);
        }
    }
    set_len(new_len);
    0
}

extern "C" fn stat(path: McxPath, out_mode: *mut u16, out_size: *mut u64) -> i32 {
    let Some(path) = (unsafe { path_bytes(path) }) else {
        return -22;
    };
    if out_mode.is_null() || out_size.is_null() {
        return -22;
    }
    unsafe {
        if is_bench_dir(path) {
            *out_mode = 0x4000 | 0o755;
            *out_size = 0;
            return 0;
        }
        if is_bench_file(path) {
            *out_mode = FILE_MODE;
            *out_size = current_len() as u64;
            return 0;
        }
    }
    -2
}

extern "C" fn readdir(path: McxPath, buf: McxBuffer, out_len: *mut usize) -> i32 {
    let Some(path) = (unsafe { path_bytes(path) }) else {
        return -22;
    };
    if buf.ptr.is_null() || out_len.is_null() {
        return -22;
    }
    let entries: &[u8] = if path == b"/" {
        b"bench"
    } else if is_bench_dir(path) {
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

static FS_OPS: McxFsOps = McxFsOps {
    mount,
    set_disk_ops,
    create,
    remove,
    rename,
    read,
    write,
    truncate,
    stat,
    readdir,
};

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn _start() -> *const McxFsOps {
    &FS_OPS
}

#[used]
#[link_section = ".data.mochi.init"]
static KEEP_MOCHI_MODULE_INIT: extern "C" fn() -> *const McxFsOps = _start;

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn mochi_module_init() -> *const McxFsOps {
    _start()
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
