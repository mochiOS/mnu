use alloc::string::String;
use alloc::vec::Vec;

pub fn register(_ops: *const super::McxFsOps, _version: u16) -> bool {
    false
}

pub fn is_loaded() -> bool {
    false
}

pub fn is_mounted() -> bool {
    false
}

pub fn mount(_device_id: u32) -> i32 {
    -38
}

pub fn set_disk_ops(_disk_ops: *const crate::kmod::disk::McxDiskOps) -> i32 {
    -38
}

pub fn create(_path: &str, _mode: u32) -> i32 {
    -38
}

pub fn remove(_path: &str, _is_dir: bool) -> i32 {
    -38
}

pub fn rename(_src: &str, _dst: &str) -> i32 {
    -38
}

pub fn read_all(path: &str) -> Option<Vec<u8>> {
    crate::init::fs::kernel_read_initfs(path)
}

pub fn write_all(_path: &str, _offset: u64, _data: &[u8]) -> Option<usize> {
    None
}

pub fn truncate(_path: &str, _len: u64) -> i32 {
    -38
}

pub fn file_metadata(path: &str) -> Option<(u16, u64)> {
    crate::init::fs::file_metadata(path)
}

pub fn is_directory(path: &str) -> bool {
    crate::init::fs::is_directory(path)
}

pub fn readdir_path(path: &str) -> Option<Vec<String>> {
    crate::init::fs::readdir_path(path)
}

pub fn register_builtin_bench_fs() -> bool {
    false
}
