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
    valid_len: usize,
    last_used: u64,
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

    fn page_with_len(
        &self,
        page_index: u64,
    ) -> Result<(Arc<[u8; PAGE_BYTES]>, usize), u64> {
        let key = PageKey {
            mount_id: self.vnode.inode.mount_id,
            inode_id: self.vnode.inode.inode_id,
            page_index,
        };
        if let Some(page) = cached_page(key) {
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
        if cache.len() == MAX_CACHED_PAGES {
            let lru = cache
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(index, _)| index)
                .unwrap_or(0);
            cache.swap_remove(lru);
        }
        cache.push(CachedPage {
            key,
            bytes: bytes.clone(),
            valid_len,
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
            output[copied..copied + count]
                .copy_from_slice(&page[page_offset..page_offset + count]);
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

fn cached_page(key: PageKey) -> Option<(Arc<[u8; PAGE_BYTES]>, usize)> {
    let mut cache = PAGE_CACHE.lock();
    let entry = cache.iter_mut().find(|entry| entry.key == key)?;
    entry.last_used = next_cache_access();
    Some((entry.bytes.clone(), entry.valid_len))
}

fn next_cache_access() -> u64 {
    PAGE_CACHE_CLOCK.fetch_add(1, Ordering::Relaxed)
}

pub fn invalidate_inode(mount_id: MountId, inode_id: InodeId) {
    PAGE_CACHE
        .lock()
        .retain(|entry| entry.key.mount_id != mount_id || entry.key.inode_id != inode_id);
}

fn update_cached_range(mount_id: MountId, inode_id: InodeId, offset: u64, input: &[u8]) {
    if input.is_empty() {
        return;
    }
    let end = offset.saturating_add(input.len() as u64);
    let mut cache = PAGE_CACHE.lock();
    for entry in cache.iter_mut().filter(|entry| {
        entry.key.mount_id == mount_id && entry.key.inode_id == inode_id
    }) {
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
        let mut bytes = *entry.bytes;
        bytes[page_offset..page_offset + count]
            .copy_from_slice(&input[input_start..input_start + count]);
        entry.bytes = Arc::new(bytes);
        entry.valid_len = core::cmp::max(entry.valid_len, page_offset + count);
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
    });
}

pub fn truncate_inode(mount_id: MountId, inode_id: InodeId, length: u64) {
    let first_invalid_page = length / PAGE_BYTES as u64;
    PAGE_CACHE.lock().retain(|entry| {
        entry.key.mount_id != mount_id
            || entry.key.inode_id != inode_id
            || entry.key.page_index < first_invalid_page
    });
}
