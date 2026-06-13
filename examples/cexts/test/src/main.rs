#![no_std]
#![no_main]

use core::sync::atomic::{AtomicUsize, Ordering};

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

const TEST_DIR: &[u8] = b"/test";
const TEST_FILE: &[u8] = b"/test/mock.bin";
const TEST_DATA: &[u8] = b"mock-cext test data\n";
const FILE_MODE: u16 = 0x8000 | 0o644;
const BUFFER_CAP: usize = 4096;

static mut BUFFER: [u8; BUFFER_CAP] = [0; BUFFER_CAP];
static LENGTH: AtomicUsize = AtomicUsize::new(0);

#[inline]
unsafe fn path_bytes<'a>(path: McxPath) -> Option<&'a [u8]> {
    if path.ptr.is_null() {
        return None;
    }
    Some(core::slice::from_raw_parts(path.ptr, path.len))
}

fn set_length(len: usize) {
    LENGTH.store(len, Ordering::Release);
}

fn current_length() -> usize {
    LENGTH.load(Ordering::Acquire)
}

extern "C" fn mount(_device_id: u32) -> i32 {
    0
}

extern "C" fn set_disk_ops(_ops: *const McxDiskOps) -> i32 {
    0
}

extern "C" fn create(path: McxPath, _mode: u32) -> i32 {
    let Some(path) = (unsafe { path_bytes(path) }) else {
        return -22;
    };
    if path == TEST_FILE {
        set_length(0);
        0
    } else {
        -2
    }
}

extern "C" fn remove(path: McxPath, _is_dir: u32) -> i32 {
    let Some(path) = (unsafe { path_bytes(path) }) else {
        return -22;
    };
    if path == TEST_FILE || path == TEST_DIR {
        set_length(0);
        0
    } else {
        -2
    }
}

extern "C" fn rename(_src: McxPath, _dst: McxPath) -> i32 {
    -2
}

extern "C" fn read(path: McxPath, offset: u64, buf: McxBuffer, out_read: *mut usize) -> i32 {
    let Some(path) = (unsafe { path_bytes(path) }) else {
        return -22;
    };
    if path != TEST_FILE || buf.ptr.is_null() || out_read.is_null() {
        return -22;
    }
    let source = TEST_DATA;
    let start = core::cmp::min(offset as usize, source.len());
    let to_copy = core::cmp::min(source.len() - start, buf.len);
    unsafe {
        core::ptr::copy_nonoverlapping(source[start..].as_ptr(), buf.ptr, to_copy);
        *out_read = to_copy;
    }
    0
}

extern "C" fn write(path: McxPath, offset: u64, buf: McxBuffer, out_written: *mut usize) -> i32 {
    let Some(path) = (unsafe { path_bytes(path) }) else {
        return -22;
    };
    if path != TEST_FILE || buf.ptr.is_null() || out_written.is_null() {
        return -22;
    }
    let start = core::cmp::min(offset as usize, BUFFER_CAP);
    let max_copy = BUFFER_CAP.saturating_sub(start);
    let to_copy = core::cmp::min(max_copy, buf.len);
    unsafe {
        let dst = core::ptr::addr_of_mut!(BUFFER) as *mut u8;
        core::ptr::copy_nonoverlapping(buf.ptr, dst.add(start), to_copy);
        *out_written = to_copy;
    }
    let end = start.saturating_add(to_copy);
    if end > current_length() {
        set_length(end);
    }
    0
}

extern "C" fn truncate(path: McxPath, len: u64) -> i32 {
    let Some(path) = (unsafe { path_bytes(path) }) else {
        return -22;
    };
    if path != TEST_FILE {
        return -2;
    }
    set_length(core::cmp::min(len as usize, BUFFER_CAP));
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
        if path == TEST_DIR {
            *out_mode = 0x4000 | 0o755;
            *out_size = 0;
            return 0;
        }
        if path == TEST_FILE {
            *out_mode = FILE_MODE;
            *out_size = current_length() as u64;
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
    let entries = if path == b"/" {
        &b"test"[..]
    } else if path == TEST_DIR {
        &b"mock.bin"[..]
    } else {
        return -2;
    };
    let to_copy = core::cmp::min(entries.len(), buf.len);
    unsafe {
        core::ptr::copy_nonoverlapping(entries.as_ptr(), buf.ptr, to_copy);
        *out_len = to_copy;
    }
    0
}

static OPS: McxFsOps = McxFsOps {
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
pub extern "C" fn mochi_module_init() -> *const McxFsOps {
    &OPS
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn _start() -> *const McxFsOps {
    mochi_module_init()
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
