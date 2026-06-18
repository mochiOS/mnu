use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

#[derive(Clone, Debug)]
struct OverlayEntry {
    mode: u16,
    data: Vec<u8>,
    removed: bool,
}

static LOADED: AtomicBool = AtomicBool::new(true);
static OVERLAY: Mutex<Option<BTreeMap<String, OverlayEntry>>> = Mutex::new(None);
const MAX_OVERLAY_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_OVERLAY_FILE_BYTES: usize = 8 * 1024 * 1024;

fn with_overlay_mut<R>(f: impl FnOnce(&mut BTreeMap<String, OverlayEntry>) -> R) -> R {
    let mut guard = OVERLAY.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

fn with_overlay<R>(f: impl FnOnce(&BTreeMap<String, OverlayEntry>) -> R) -> R {
    let mut guard = OVERLAY.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        alloc::format!("/{}", parts.join("/"))
    }
}

fn parent_path(path: &str) -> Option<String> {
    let path = normalize_path(path);
    if path == "/" {
        return None;
    }
    let mut parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    parts.pop();
    if parts.is_empty() {
        Some("/".to_string())
    } else {
        Some(alloc::format!("/{}", parts.join("/")))
    }
}

fn entry_name(path: &str) -> Option<String> {
    let path = normalize_path(path);
    if path == "/" {
        None
    } else {
        path.rsplit('/').next().map(|s| s.to_string())
    }
}

fn base_metadata(path: &str) -> Option<(u16, u64)> {
    crate::init::fs::file_metadata(path)
}

fn base_is_directory(path: &str) -> bool {
    crate::init::fs::is_directory(path)
}

fn base_read(path: &str) -> Option<Vec<u8>> {
    crate::init::fs::read(path)
}

fn base_readdir(path: &str) -> Option<Vec<String>> {
    crate::init::fs::readdir_path(path)
}

fn overlay_entry(path: &str) -> Option<OverlayEntry> {
    with_overlay(|map| map.get(path).cloned())
}

fn effective_entry(path: &str) -> Option<OverlayEntry> {
    if let Some(entry) = overlay_entry(path) {
        if entry.removed {
            return None;
        }
        return Some(entry);
    }
    None
}

fn mode_for_file(mode: Option<u16>) -> u16 {
    mode.unwrap_or(0o100644)
}

fn overlay_total_bytes(map: &BTreeMap<String, OverlayEntry>) -> usize {
    map.values()
        .filter(|entry| !entry.removed)
        .map(|entry| entry.data.len())
        .sum()
}

pub fn is_loaded() -> bool {
    LOADED.load(Ordering::Acquire)
}

pub fn mount(_device_id: u32) -> i32 {
    0
}

pub fn set_disk_ops(_disk_ops: *const crate::cext::disk::McxDiskOps) -> i32 {
    0
}

pub fn create(path: &str, mode: u32) -> i32 {
    let path = normalize_path(path);
    if path == "/" {
        return -21;
    }
    if base_is_directory(&path) {
        return -17;
    }
    with_overlay_mut(|map| {
        map.insert(
            path,
            OverlayEntry {
                mode: mode_for_file(Some(mode as u16)),
                data: Vec::new(),
                removed: false,
            },
        );
    });
    0
}

pub fn remove(path: &str, is_dir: bool) -> i32 {
    let path = normalize_path(path);
    if path == "/" {
        return -13;
    }
    if let Some((mode, _)) = base_metadata(&path) {
        let base_is_dir = (mode & 0xF000) == 0x4000;
        if is_dir && !base_is_dir {
            return -20;
        }
        if !is_dir && base_is_dir {
            return -21;
        }
    } else if overlay_entry(&path).is_none() {
        return -2;
    }
    with_overlay_mut(|map| {
        map.entry(path)
            .and_modify(|entry| entry.removed = true)
            .or_insert_with(|| OverlayEntry {
                mode: if is_dir { 0o040755 } else { 0o100644 },
                data: Vec::new(),
                removed: true,
            });
    });
    0
}

pub fn rename(src: &str, dst: &str) -> i32 {
    let src = normalize_path(src);
    let dst = normalize_path(dst);
    if src == "/" || dst == "/" {
        return -13;
    }
    let meta = file_metadata(&src);
    let Some((mode, size)) = meta else {
        return -2;
    };
    let data = read_all(&src).unwrap_or_default();
    with_overlay_mut(|map| {
        map.insert(
            dst.clone(),
            OverlayEntry {
                mode,
                data: data.clone(),
                removed: false,
            },
        );
        map.insert(
            src,
            OverlayEntry {
                mode: mode_for_file(Some(mode)),
                data: Vec::new(),
                removed: true,
            },
        );
    });
    let _ = size;
    0
}

pub fn read_all(path: &str) -> Option<Vec<u8>> {
    let path = normalize_path(path);
    if let Some(entry) = effective_entry(&path) {
        return Some(entry.data);
    }
    base_read(&path)
}

pub fn write_all(path: &str, offset: u64, data: &[u8]) -> Option<usize> {
    let path = normalize_path(path);
    if path == "/" {
        return None;
    }
    let mut entry = effective_entry(&path).or_else(|| {
        base_metadata(&path).map(|(mode, _)| OverlayEntry {
            mode,
            data: base_read(&path).unwrap_or_default(),
            removed: false,
        })
    });
    if entry.is_none() {
        entry = Some(OverlayEntry {
            mode: 0o100644,
            data: Vec::new(),
            removed: false,
        });
    }
    let mut entry = entry?;
    if (entry.mode & 0xF000) == 0x4000 {
        return None;
    }
    let off = usize::try_from(offset).ok()?;
    let end = off.checked_add(data.len())?;
    if end > MAX_OVERLAY_FILE_BYTES {
        return None;
    }
    let projected = with_overlay(|map| {
        let current = map.get(&path).map(|e| e.data.len()).unwrap_or(0);
        let total = overlay_total_bytes(map);
        total
            .saturating_sub(current)
            .saturating_add(end.max(current))
    });
    if projected > MAX_OVERLAY_TOTAL_BYTES {
        return None;
    }
    if end > entry.data.len() {
        entry.data.resize(end, 0);
    }
    entry.data[off..end].copy_from_slice(data);
    with_overlay_mut(|map| {
        map.insert(path, entry.clone());
    });
    Some(data.len())
}

pub fn truncate(path: &str, len: u64) -> i32 {
    let path = normalize_path(path);
    if path == "/" {
        return -21;
    }
    let Some((mode, _)) = file_metadata(&path) else {
        return -2;
    };
    if (mode & 0xF000) == 0x4000 {
        return -21;
    }
    let new_len = match usize::try_from(len) {
        Ok(v) => v,
        Err(_) => return -22,
    };
    if new_len > MAX_OVERLAY_FILE_BYTES {
        return -28;
    }
    let projected = with_overlay(|map| {
        let current = map.get(&path).map(|e| e.data.len()).unwrap_or(0);
        let total = overlay_total_bytes(map);
        total
            .saturating_sub(current)
            .saturating_add(new_len.max(current))
    });
    if projected > MAX_OVERLAY_TOTAL_BYTES {
        return -28;
    }
    let mut data = read_all(&path).unwrap_or_default();
    data.resize(new_len, 0);
    with_overlay_mut(|map| {
        map.insert(
            path,
            OverlayEntry {
                mode: mode_for_file(Some(mode)),
                data,
                removed: false,
            },
        );
    });
    0
}

pub fn file_metadata(path: &str) -> Option<(u16, u64)> {
    let path = normalize_path(path);
    if let Some(entry) = overlay_entry(&path) {
        if entry.removed {
            return None;
        }
        return Some((entry.mode, entry.data.len() as u64));
    }
    base_metadata(&path)
}

pub fn is_directory(path: &str) -> bool {
    file_metadata(path)
        .map(|(mode, _)| (mode & 0xF000) == 0x4000)
        .unwrap_or(false)
}

pub fn readdir_path(path: &str) -> Option<Vec<String>> {
    let path = normalize_path(path);
    if !is_directory(&path) {
        return None;
    }

    let mut names = base_readdir(&path).unwrap_or_default();
    with_overlay(|map| {
        for (entry_path, entry) in map.iter() {
            if entry.removed {
                continue;
            }
            if parent_path(entry_path).as_deref() != Some(path.as_str()) {
                continue;
            }
            if let Some(name) = entry_name(entry_path) {
                if !names.iter().any(|n| n == &name) {
                    names.push(name);
                }
            }
        }
    });
    names.sort();
    Some(names)
}
