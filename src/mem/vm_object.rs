//! VM objects and a bounded vnode page cache.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::interrupt::spinlock::SpinLock;
use crate::vfs::{InodeId, MountId, Vnode};

pub const PAGE_BYTES: usize = 4096;
const MAX_CACHED_PAGES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PageKey {
    mount_id: MountId,
    inode_id: InodeId,
    page_index: u64,
}

struct CachedPage {
    key: PageKey,
    bytes: Arc<[u8; PAGE_BYTES]>,
    frame_phys: Option<u64>,
    valid_len: usize,
    dirty_range: Option<(usize, usize)>,
    version: u64,
    last_used: u64,
}

impl Drop for CachedPage {
    fn drop(&mut self) {
        if let Some(frame_phys) = self.frame_phys {
            crate::mem::paging::release_user_frame(frame_phys);
        }
    }
}

static PAGE_CACHE: SpinLock<Vec<CachedPage>> = SpinLock::new(Vec::new());
static PAGE_CACHE_CLOCK: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct VmObject {
    vnode: Arc<Vnode>,
}

impl VmObject {
    pub fn file(vnode: Arc<Vnode>) -> Self {
        Self { vnode }
    }

    pub fn vnode(&self) -> &Arc<Vnode> {
        &self.vnode
    }

    pub fn page(&self, page_index: u64) -> Result<Arc<[u8; PAGE_BYTES]>, u64> {
        self.page_with_len(page_index).map(|(bytes, _)| bytes)
    }

    fn page_with_len(&self, page_index: u64) -> Result<(Arc<[u8; PAGE_BYTES]>, usize), u64> {
        let key = PageKey {
            mount_id: self.vnode.inode.mount_id,
            inode_id: self.vnode.inode.inode_id,
            page_index,
        };
        if let Some(page) = cached_page(key)? {
            return Ok(page);
        }

        let offset = page_index
            .checked_mul(PAGE_BYTES as u64)
            .ok_or(crate::syscall::EINVAL)?;
        let mut page = [0u8; PAGE_BYTES];
        let valid_len = self.vnode.read_at(offset, &mut page)?;
        let bytes = Arc::new(page);

        let mut cache = PAGE_CACHE.lock();
        if let Some(existing) = cache.iter_mut().find(|entry| entry.key == key) {
            existing.last_used = next_cache_access();
            return Ok((existing.bytes.clone(), existing.valid_len));
        }
        if cache.len() >= MAX_CACHED_PAGES {
            if let Some(lru) = cache
                .iter()
                .enumerate()
                .filter(|(_, entry)| cache_entry_is_evictable(entry))
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(index, _)| index)
            {
                cache.swap_remove(lru);
            } else {
                // Dirty pages must survive until writeback. Serve this clean
                // page without caching it rather than growing on read misses.
                return Ok((bytes, valid_len));
            }
        }
        cache.push(CachedPage {
            key,
            bytes: bytes.clone(),
            frame_phys: None,
            valid_len,
            dirty_range: None,
            version: 0,
            last_used: next_cache_access(),
        });
        Ok((bytes, valid_len))
    }

    pub fn invalidate(&self) {
        invalidate_inode(self.vnode.inode.mount_id, self.vnode.inode.inode_id);
    }

    pub fn read_at(&self, offset: u64, output: &mut [u8]) -> Result<usize, u64> {
        let mut copied = 0usize;
        while copied < output.len() {
            let current = offset
                .checked_add(copied as u64)
                .ok_or(crate::syscall::EINVAL)?;
            let page_index = current / PAGE_BYTES as u64;
            let page_offset = (current % PAGE_BYTES as u64) as usize;
            let (page, valid_len) = self.page_with_len(page_index)?;
            if page_offset >= valid_len {
                break;
            }
            let count = core::cmp::min(
                output.len() - copied,
                core::cmp::min(PAGE_BYTES - page_offset, valid_len - page_offset),
            );
            output[copied..copied + count].copy_from_slice(&page[page_offset..page_offset + count]);
            copied += count;
            if valid_len < PAGE_BYTES {
                break;
            }
        }
        Ok(copied)
    }

    pub fn write_at(&self, offset: u64, input: &[u8]) -> Result<usize, u64> {
        let written = self.vnode.write_at(offset, input)?;
        update_cached_range(
            self.vnode.inode.mount_id,
            self.vnode.inode.inode_id,
            offset,
            &input[..written],
        );
        Ok(written)
    }

    pub fn map_shared_page(
        &self,
        table_phys: u64,
        virt_addr: u64,
        page_index: u64,
        writable: bool,
        executable: bool,
    ) -> Result<(), u64> {
        let (loaded, loaded_len) = self.page_with_len(page_index)?;
        let key = PageKey {
            mount_id: self.vnode.inode.mount_id,
            inode_id: self.vnode.inode.inode_id,
            page_index,
        };

        let mut cache = PAGE_CACHE.lock();
        let entry_index = if let Some(index) = cache.iter().position(|entry| entry.key == key) {
            index
        } else {
            cache.push(CachedPage {
                key,
                bytes: loaded,
                frame_phys: None,
                valid_len: loaded_len,
                dirty_range: None,
                version: 0,
                last_used: next_cache_access(),
            });
            cache.len() - 1
        };
        if cache[entry_index].frame_phys.is_none() {
            let frame =
                crate::mem::frame::allocate_zeroed_frame().map_err(|_| crate::syscall::ENOMEM)?;
            let frame_phys = frame.start_address().as_u64();
            if let Err(errno) = copy_to_frame(frame_phys, 0, cache[entry_index].bytes.as_slice()) {
                let _ = crate::mem::frame::deallocate_frame(frame);
                return Err(errno);
            }
            cache[entry_index].frame_phys = Some(frame_phys);
        }
        let frame_phys = cache[entry_index]
            .frame_phys
            .ok_or(crate::syscall::ENOMEM)?;
        crate::mem::paging::map_shared_frame_to_user(
            table_phys, virt_addr, frame_phys, writable, executable,
        )
        .map_err(|_| crate::syscall::ENOMEM)?;
        cache[entry_index].last_used = next_cache_access();
        Ok(())
    }

    pub fn mark_page_dirty(&self, page_index: u64) -> Result<(), u64> {
        let key = PageKey {
            mount_id: self.vnode.inode.mount_id,
            inode_id: self.vnode.inode.inode_id,
            page_index,
        };
        let mut cache = PAGE_CACHE.lock();
        let entry = cache
            .iter_mut()
            .find(|entry| entry.key == key && entry.frame_phys.is_some())
            .ok_or(crate::syscall::EIO)?;
        entry.valid_len = PAGE_BYTES;
        entry.dirty_range = Some((0, PAGE_BYTES));
        entry.version = entry.version.wrapping_add(1);
        entry.last_used = next_cache_access();
        Ok(())
    }

    /// Stages a write in the shared page cache without writing it to storage.
    pub fn stage_write_at(&self, offset: u64, input: &[u8]) -> Result<usize, u64> {
        let mut staged = 0usize;
        while staged < input.len() {
            let current = offset
                .checked_add(staged as u64)
                .ok_or(crate::syscall::EINVAL)?;
            let page_index = current / PAGE_BYTES as u64;
            let page_offset = (current % PAGE_BYTES as u64) as usize;
            let count = core::cmp::min(input.len() - staged, PAGE_BYTES - page_offset);
            let (loaded, loaded_len) = self.page_with_len(page_index)?;
            let key = PageKey {
                mount_id: self.vnode.inode.mount_id,
                inode_id: self.vnode.inode.inode_id,
                page_index,
            };

            let mut cache = PAGE_CACHE.lock();
            let entry_index = if let Some(index) = cache.iter().position(|entry| entry.key == key) {
                index
            } else {
                cache.push(CachedPage {
                    key,
                    bytes: loaded,
                    frame_phys: None,
                    valid_len: loaded_len,
                    dirty_range: None,
                    version: 0,
                    last_used: next_cache_access(),
                });
                cache.len() - 1
            };
            let entry = &mut cache[entry_index];
            let mut bytes = *snapshot_page(entry)?;
            bytes[page_offset..page_offset + count].copy_from_slice(&input[staged..staged + count]);
            entry.bytes = Arc::new(bytes);
            if let Some(frame_phys) = entry.frame_phys {
                copy_to_frame(frame_phys, page_offset, &input[staged..staged + count])?;
            }
            entry.valid_len = core::cmp::max(entry.valid_len, page_offset + count);
            entry.dirty_range = Some(match entry.dirty_range {
                Some((start, end)) => (
                    core::cmp::min(start, page_offset),
                    core::cmp::max(end, page_offset + count),
                ),
                None => (page_offset, page_offset + count),
            });
            entry.version = entry.version.wrapping_add(1);
            entry.last_used = next_cache_access();
            staged += count;
        }
        Ok(staged)
    }

    /// Writes dirty cache pages intersecting the range back to their vnode.
    pub fn flush_range(&self, offset: u64, length: u64) -> Result<(), u64> {
        if length == 0 {
            return Ok(());
        }
        let range_end = offset.saturating_add(length);
        let snapshots = {
            let mut cache = PAGE_CACHE.lock();
            let mut snapshots = Vec::new();
            for entry in cache.iter_mut().filter(|entry| {
                entry.key.mount_id == self.vnode.inode.mount_id
                    && entry.key.inode_id == self.vnode.inode.inode_id
            }) {
                let page_start = entry.key.page_index.saturating_mul(PAGE_BYTES as u64);
                let page_end = page_start.saturating_add(PAGE_BYTES as u64);
                if page_start >= range_end || page_end <= offset {
                    continue;
                }
                let Some((dirty_start, dirty_end)) = entry.dirty_range else {
                    continue;
                };
                entry.last_used = next_cache_access();
                snapshots.push((
                    entry.key,
                    snapshot_page(entry)?,
                    dirty_start,
                    dirty_end,
                    entry.version,
                ));
            }
            snapshots
        };

        for (key, bytes, dirty_start, dirty_end, version) in snapshots {
            let page_start = key
                .page_index
                .checked_mul(PAGE_BYTES as u64)
                .ok_or(crate::syscall::EINVAL)?;
            let write_offset = page_start
                .checked_add(dirty_start as u64)
                .ok_or(crate::syscall::EINVAL)?;
            let written = self
                .vnode
                .write_at(write_offset, &bytes[dirty_start..dirty_end])?;
            if written != dirty_end - dirty_start {
                return Err(crate::syscall::EIO);
            }

            let mut cache = PAGE_CACHE.lock();
            if let Some(entry) = cache
                .iter_mut()
                .find(|entry| entry.key == key && entry.version == version)
            {
                entry.dirty_range = None;
                entry.last_used = next_cache_access();
            }
        }
        Ok(())
    }

    pub fn flush(&self) -> Result<(), u64> {
        self.flush_range(0, u64::MAX)
    }
}

impl core::fmt::Debug for VmObject {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VmObject")
            .field("mount_id", &self.vnode.inode.mount_id)
            .field("inode_id", &self.vnode.inode.inode_id)
            .finish()
    }
}

fn cached_page(key: PageKey) -> Result<Option<(Arc<[u8; PAGE_BYTES]>, usize)>, u64> {
    let mut cache = PAGE_CACHE.lock();
    let Some(entry) = cache.iter_mut().find(|entry| entry.key == key) else {
        return Ok(None);
    };
    entry.last_used = next_cache_access();
    Ok(Some((snapshot_page(entry)?, entry.valid_len)))
}

fn snapshot_page(entry: &CachedPage) -> Result<Arc<[u8; PAGE_BYTES]>, u64> {
    let Some(frame_phys) = entry.frame_phys else {
        return Ok(entry.bytes.clone());
    };
    let physical_offset =
        crate::mem::paging::physical_memory_offset().ok_or(crate::syscall::EIO)?;
    let mut bytes = [0u8; PAGE_BYTES];
    unsafe {
        core::ptr::copy_nonoverlapping(
            (frame_phys + physical_offset) as *const u8,
            bytes.as_mut_ptr(),
            PAGE_BYTES,
        );
    }
    Ok(Arc::new(bytes))
}

fn copy_to_frame(frame_phys: u64, offset: usize, input: &[u8]) -> Result<(), u64> {
    let end = offset
        .checked_add(input.len())
        .filter(|end| *end <= PAGE_BYTES)
        .ok_or(crate::syscall::EINVAL)?;
    let physical_offset =
        crate::mem::paging::physical_memory_offset().ok_or(crate::syscall::EIO)?;
    unsafe {
        core::ptr::copy_nonoverlapping(
            input.as_ptr(),
            (frame_phys + physical_offset + offset as u64) as *mut u8,
            end - offset,
        );
    }
    Ok(())
}

fn cache_entry_is_evictable(entry: &CachedPage) -> bool {
    entry.dirty_range.is_none()
        && entry
            .frame_phys
            .is_none_or(|phys| !crate::mem::paging::user_frame_has_multiple_owners(phys))
}

fn next_cache_access() -> u64 {
    PAGE_CACHE_CLOCK.fetch_add(1, Ordering::Relaxed)
}

pub fn invalidate_inode(mount_id: MountId, inode_id: InodeId) {
    PAGE_CACHE.lock().retain(|entry| {
        entry.key.mount_id != mount_id
            || entry.key.inode_id != inode_id
            || entry
                .frame_phys
                .is_some_and(crate::mem::paging::user_frame_has_multiple_owners)
    });
}

fn update_cached_range(mount_id: MountId, inode_id: InodeId, offset: u64, input: &[u8]) {
    if input.is_empty() {
        return;
    }
    let end = offset.saturating_add(input.len() as u64);
    let mut cache = PAGE_CACHE.lock();
    for entry in cache
        .iter_mut()
        .filter(|entry| entry.key.mount_id == mount_id && entry.key.inode_id == inode_id)
    {
        let page_start = entry.key.page_index.saturating_mul(PAGE_BYTES as u64);
        let page_end = page_start.saturating_add(PAGE_BYTES as u64);
        let copy_start = core::cmp::max(offset, page_start);
        let copy_end = core::cmp::min(end, page_end);
        if copy_start >= copy_end {
            continue;
        }
        let input_start = (copy_start - offset) as usize;
        let page_offset = (copy_start - page_start) as usize;
        let count = (copy_end - copy_start) as usize;
        let mut bytes = match snapshot_page(entry) {
            Ok(bytes) => *bytes,
            Err(_) => continue,
        };
        bytes[page_offset..page_offset + count]
            .copy_from_slice(&input[input_start..input_start + count]);
        entry.bytes = Arc::new(bytes);
        if let Some(frame_phys) = entry.frame_phys {
            if copy_to_frame(
                frame_phys,
                page_offset,
                &input[input_start..input_start + count],
            )
            .is_err()
            {
                continue;
            }
        }
        entry.valid_len = core::cmp::max(entry.valid_len, page_offset + count);
        entry.version = entry.version.wrapping_add(1);
        entry.last_used = next_cache_access();
    }
}

pub fn invalidate_range(mount_id: MountId, inode_id: InodeId, offset: u64, length: u64) {
    if length == 0 {
        return;
    }
    let first_page = offset / PAGE_BYTES as u64;
    let last_page = offset.saturating_add(length - 1) / PAGE_BYTES as u64;
    PAGE_CACHE.lock().retain(|entry| {
        entry.key.mount_id != mount_id
            || entry.key.inode_id != inode_id
            || entry.key.page_index < first_page
            || entry.key.page_index > last_page
            || entry
                .frame_phys
                .is_some_and(crate::mem::paging::user_frame_has_multiple_owners)
    });
}

pub fn truncate_inode(mount_id: MountId, inode_id: InodeId, length: u64) {
    let first_invalid_page = length / PAGE_BYTES as u64;
    PAGE_CACHE.lock().retain_mut(|entry| {
        if entry.key.mount_id != mount_id
            || entry.key.inode_id != inode_id
            || entry.key.page_index < first_invalid_page
        {
            return true;
        }
        let Some(frame_phys) = entry.frame_phys else {
            return false;
        };
        if !crate::mem::paging::user_frame_has_multiple_owners(frame_phys) {
            return false;
        }
        let page_start = entry.key.page_index.saturating_mul(PAGE_BYTES as u64);
        let valid_len = length.saturating_sub(page_start).min(PAGE_BYTES as u64) as usize;
        let mut bytes = snapshot_page(entry)
            .map(|bytes| *bytes)
            .unwrap_or([0u8; PAGE_BYTES]);
        bytes[valid_len..].fill(0);
        entry.bytes = Arc::new(bytes);
        let _ = copy_to_frame(frame_phys, valid_len, &bytes[valid_len..]);
        entry.valid_len = valid_len;
        entry.dirty_range = None;
        entry.version = entry.version.wrapping_add(1);
        entry.last_used = next_cache_access();
        true
    });
}
