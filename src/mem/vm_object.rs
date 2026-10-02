//! VM objects and a bounded vnode page cache.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::interrupt::spinlock::SpinLock;
use crate::vfs::{InodeId, MountId, Vnode};

pub const PAGE_BYTES: usize = 4096;
const MAX_CACHED_PAGES: usize = 256;
const MAX_READ_BATCH_BYTES: usize = 256 * 1024;

static PAGE_CACHE_MUTATION_EPOCH: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
struct LowerReadOutcome {
    bytes_read: usize,
    eof: bool,
    error: Option<u64>,
}

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

        let epoch = cache_mutation_epoch();
        let mut page = [0u8; PAGE_BYTES];
        let outcome = read_lower_until(&self.vnode, offset, &mut page);

        if let Some(errno) = outcome.error {
            return Err(errno);
        }

        let valid_len = outcome.bytes_read;
        let bytes = Arc::new(page);

        if let Some(existing) =
            cache_or_snapshot_page(key, &bytes[..valid_len], valid_len, Some(epoch))?
        {
            return Ok(existing);
        }

        Ok((bytes, valid_len))
    }

    pub fn invalidate(&self) {
        invalidate_inode(self.vnode.inode.mount_id, self.vnode.inode.inode_id);
    }

    pub fn read_at(&self, offset: u64, output: &mut [u8]) -> Result<usize, u64> {
        if output.is_empty() {
            return Ok(0);
        }

        let output_len = u64::try_from(output.len()).map_err(|_| crate::syscall::EINVAL)?;

        offset
            .checked_add(output_len)
            .ok_or(crate::syscall::EINVAL)?;

        let lower_limit = self.vnode.read_io_limit();
        let batch_limit = if lower_limit >= PAGE_BYTES {
            core::cmp::min(MAX_READ_BATCH_BYTES, lower_limit)
        } else {
            PAGE_BYTES
        };

        let max_batch_pages = core::cmp::max(1, batch_limit / PAGE_BYTES);

        let mut copied = 0usize;

        while copied < output.len() {
            let copied_u64 = u64::try_from(copied).map_err(|_| crate::syscall::EINVAL)?;

            let current = offset
                .checked_add(copied_u64)
                .ok_or(crate::syscall::EINVAL)?;

            let page_index = current / PAGE_BYTES as u64;
            let page_offset = (current % PAGE_BYTES as u64) as usize;

            let key = PageKey {
                mount_id: self.vnode.inode.mount_id,
                inode_id: self.vnode.inode.inode_id,
                page_index,
            };

            if let Some((page, valid_len)) = cached_page(key)? {
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

                continue;
            }

            let remaining = output.len() - copied;

            let covered_bytes = page_offset
                .checked_add(remaining)
                .ok_or(crate::syscall::EINVAL)?;

            let pages_needed = covered_bytes
                .checked_add(PAGE_BYTES - 1)
                .ok_or(crate::syscall::EINVAL)?
                / PAGE_BYTES;

            let wanted_pages = core::cmp::min(pages_needed, max_batch_pages);

            let batch_pages = contiguous_uncached_pages(
                self.vnode.inode.mount_id,
                self.vnode.inode.inode_id,
                page_index,
                wanted_pages,
            );

            if batch_pages == 0 {
                continue;
            }

            let batch_len = batch_pages
                .checked_mul(PAGE_BYTES)
                .ok_or(crate::syscall::EINVAL)?;

            let batch_offset = page_index
                .checked_mul(PAGE_BYTES as u64)
                .ok_or(crate::syscall::EINVAL)?;

            let epoch = cache_mutation_epoch();

            let mut batch = alloc::vec![0u8; batch_len];

            let outcome = read_lower_until(&self.vnode, batch_offset, &mut batch);

            let copied_before_batch = copied;
            let mut stopped_on_short_page = false;

            for page_number in 0..batch_pages {
                let raw_start = page_number
                    .checked_mul(PAGE_BYTES)
                    .ok_or(crate::syscall::EINVAL)?;

                let raw_available = outcome.bytes_read.saturating_sub(raw_start).min(PAGE_BYTES);

                let page_number_u64 =
                    u64::try_from(page_number).map_err(|_| crate::syscall::EINVAL)?;

                let current_page_index = page_index
                    .checked_add(page_number_u64)
                    .ok_or(crate::syscall::EINVAL)?;

                let current_key = PageKey {
                    mount_id: self.vnode.inode.mount_id,
                    inode_id: self.vnode.inode.inode_id,
                    page_index: current_page_index,
                };

                let raw_end = raw_start
                    .checked_add(raw_available)
                    .ok_or(crate::syscall::EINVAL)?;

                let eof_page = outcome.eof && raw_end == outcome.bytes_read;

                let cacheable = raw_available == PAGE_BYTES || eof_page;

                let cached = cache_or_snapshot_page(
                    current_key,
                    &batch[raw_start..raw_end],
                    raw_available,
                    cacheable.then_some(epoch),
                )?;

                let page_start = current_page_index
                    .checked_mul(PAGE_BYTES as u64)
                    .ok_or(crate::syscall::EINVAL)?;

                let current_copied = u64::try_from(copied).map_err(|_| crate::syscall::EINVAL)?;

                let request_position = offset
                    .checked_add(current_copied)
                    .ok_or(crate::syscall::EINVAL)?;

                let page_end = page_start
                    .checked_add(PAGE_BYTES as u64)
                    .ok_or(crate::syscall::EINVAL)?;

                if request_position >= page_end {
                    continue;
                }

                if request_position < page_start {
                    return Err(crate::syscall::EIO);
                }

                let offset_in_page = usize::try_from(request_position - page_start)
                    .map_err(|_| crate::syscall::EINVAL)?;

                let valid_len = cached
                    .as_ref()
                    .map(|(_, valid_len)| *valid_len)
                    .unwrap_or(raw_available);

                if offset_in_page >= valid_len {
                    stopped_on_short_page = true;
                    break;
                }

                let count = core::cmp::min(
                    output.len() - copied,
                    core::cmp::min(PAGE_BYTES - offset_in_page, valid_len - offset_in_page),
                );

                if let Some((page, _)) = cached {
                    output[copied..copied + count]
                        .copy_from_slice(&page[offset_in_page..offset_in_page + count]);
                } else {
                    let source_start = raw_start
                        .checked_add(offset_in_page)
                        .ok_or(crate::syscall::EINVAL)?;

                    let source_end = source_start
                        .checked_add(count)
                        .ok_or(crate::syscall::EINVAL)?;

                    output[copied..copied + count]
                        .copy_from_slice(&batch[source_start..source_end]);
                }

                copied += count;

                if copied == output.len() {
                    return Ok(copied);
                }

                if valid_len < PAGE_BYTES {
                    stopped_on_short_page = true;
                    break;
                }
            }

            if stopped_on_short_page {
                if copied != 0 {
                    return Ok(copied);
                }

                if let Some(errno) = outcome.error {
                    return Err(errno);
                }

                return Ok(0);
            }

            if let Some(errno) = outcome.error {
                if copied != 0 {
                    return Ok(copied);
                }
                return Err(errno);
            }

            if outcome.eof {
                return Ok(copied);
            }

            if copied == copied_before_batch {
                return Err(crate::syscall::EIO);
            }
        }

        Ok(copied)
    }

    pub fn write_at(&self, offset: u64, input: &[u8]) -> Result<usize, u64> {
        let input_len = u64::try_from(input.len()).map_err(|_| crate::syscall::EINVAL)?;

        offset
            .checked_add(input_len)
            .ok_or(crate::syscall::EINVAL)?;

        let written = self.vnode.write_at(offset, input)?;

        if written > input.len() {
            return Err(crate::syscall::EIO);
        }

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

        if entry.valid_len != 0 {
            entry.dirty_range = Some((0, entry.valid_len));
        }

        entry.version = entry.version.wrapping_add(1);
        entry.last_used = next_cache_access();

        bump_cache_mutation_epoch();

        Ok(())
    }

    /// Stages a write in the shared page cache without writing it to storage.
    pub fn stage_write_at(&self, offset: u64, input: &[u8]) -> Result<usize, u64> {
        let input_len = u64::try_from(input.len()).map_err(|_| crate::syscall::EINVAL)?;

        offset
            .checked_add(input_len)
            .ok_or(crate::syscall::EINVAL)?;

        let mut staged = 0usize;

        while staged < input.len() {
            let staged_u64 = u64::try_from(staged).map_err(|_| crate::syscall::EINVAL)?;

            let current = offset
                .checked_add(staged_u64)
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

            let write_end = page_offset
                .checked_add(count)
                .ok_or(crate::syscall::EINVAL)?;

            bytes[page_offset..write_end].copy_from_slice(&input[staged..staged + count]);

            entry.bytes = Arc::new(bytes);

            if let Some(frame_phys) = entry.frame_phys {
                copy_to_frame(frame_phys, page_offset, &input[staged..staged + count])?;
            }

            entry.valid_len = core::cmp::max(entry.valid_len, write_end);

            entry.dirty_range = Some(match entry.dirty_range {
                Some((start, end)) => (
                    core::cmp::min(start, page_offset),
                    core::cmp::max(end, write_end),
                ),
                None => (page_offset, write_end),
            });

            entry.version = entry.version.wrapping_add(1);
            entry.last_used = next_cache_access();

            bump_cache_mutation_epoch();

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
                if !entry
                    .frame_phys
                    .is_some_and(crate::mem::paging::user_frame_has_multiple_owners)
                {
                    entry.dirty_range = None;
                }
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
    let mut cache = PAGE_CACHE.lock();

    cache.retain(|entry| {
        entry.key.mount_id != mount_id
            || entry.key.inode_id != inode_id
            || entry
                .frame_phys
                .is_some_and(crate::mem::paging::user_frame_has_multiple_owners)
    });

    bump_cache_mutation_epoch();
}

fn update_cached_range(mount_id: MountId, inode_id: InodeId, offset: u64, input: &[u8]) {
    if input.is_empty() {
        return;
    }

    let input_len = match u64::try_from(input.len()) {
        Ok(value) => value,
        Err(_) => return,
    };

    let end = match offset.checked_add(input_len) {
        Some(value) => value,
        None => return,
    };

    let mut cache = PAGE_CACHE.lock();

    for entry in cache
        .iter_mut()
        .filter(|entry| entry.key.mount_id == mount_id && entry.key.inode_id == inode_id)
    {
        let page_start = match entry.key.page_index.checked_mul(PAGE_BYTES as u64) {
            Some(value) => value,
            None => continue,
        };

        let page_end = match page_start.checked_add(PAGE_BYTES as u64) {
            Some(value) => value,
            None => continue,
        };

        let copy_start = core::cmp::max(offset, page_start);
        let copy_end = core::cmp::min(end, page_end);

        if copy_start >= copy_end {
            continue;
        }

        let input_start = match usize::try_from(copy_start - offset) {
            Ok(value) => value,
            Err(_) => continue,
        };

        let page_offset = match usize::try_from(copy_start - page_start) {
            Ok(value) => value,
            Err(_) => continue,
        };

        let count = match usize::try_from(copy_end - copy_start) {
            Ok(value) => value,
            Err(_) => continue,
        };

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

    bump_cache_mutation_epoch();
}

pub fn invalidate_range(mount_id: MountId, inode_id: InodeId, offset: u64, length: u64) {
    if length == 0 {
        return;
    }

    let first_page = offset / PAGE_BYTES as u64;

    let last_offset = offset.checked_add(length - 1).unwrap_or(u64::MAX);

    let last_page = last_offset / PAGE_BYTES as u64;

    let mut cache = PAGE_CACHE.lock();

    cache.retain(|entry| {
        entry.key.mount_id != mount_id
            || entry.key.inode_id != inode_id
            || entry.key.page_index < first_page
            || entry.key.page_index > last_page
            || entry
                .frame_phys
                .is_some_and(crate::mem::paging::user_frame_has_multiple_owners)
    });

    bump_cache_mutation_epoch();
}

pub fn truncate_inode(mount_id: MountId, inode_id: InodeId, length: u64) {
    let first_invalid_page = length / PAGE_BYTES as u64;

    let mut cache = PAGE_CACHE.lock();

    cache.retain_mut(|entry| {
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

        let Some(page_start) = entry.key.page_index.checked_mul(PAGE_BYTES as u64) else {
            return false;
        };

        let valid_len = length.saturating_sub(page_start).min(PAGE_BYTES as u64) as usize;

        let mut bytes = snapshot_page(entry)
            .map(|bytes| *bytes)
            .unwrap_or([0u8; PAGE_BYTES]);

        bytes[valid_len..].fill(0);

        entry.bytes = Arc::new(bytes);

        let _ = copy_to_frame(frame_phys, valid_len, &bytes[valid_len..]);

        entry.valid_len = valid_len;

        entry.dirty_range = (valid_len != 0).then_some((0, valid_len));

        entry.version = entry.version.wrapping_add(1);
        entry.last_used = next_cache_access();

        true
    });

    bump_cache_mutation_epoch();
}

fn read_lower_until(vnode: &Vnode, offset: u64, output: &mut [u8]) -> LowerReadOutcome {
    let mut bytes_read = 0usize;
    let io_limit = core::cmp::max(1, vnode.read_io_limit());

    while bytes_read < output.len() {
        let bytes_read_u64 = match u64::try_from(bytes_read) {
            Ok(value) => value,
            Err(_) => {
                return LowerReadOutcome {
                    bytes_read,
                    eof: false,
                    error: Some(crate::syscall::EINVAL),
                };
            }
        };

        let current = match offset.checked_add(bytes_read_u64) {
            Some(value) => value,
            None => {
                return LowerReadOutcome {
                    bytes_read,
                    eof: false,
                    error: Some(crate::syscall::EINVAL),
                };
            }
        };

        let request_len = core::cmp::min(output.len() - bytes_read, io_limit);

        match vnode.read_at(current, &mut output[bytes_read..bytes_read + request_len]) {
            Ok(0) => {
                return LowerReadOutcome {
                    bytes_read,
                    eof: true,
                    error: None,
                };
            }

            Ok(read) if read <= request_len => {
                bytes_read += read;
            }

            Ok(_) => {
                return LowerReadOutcome {
                    bytes_read,
                    eof: false,
                    error: Some(crate::syscall::EIO),
                };
            }

            Err(errno) => {
                return LowerReadOutcome {
                    bytes_read,
                    eof: false,
                    error: Some(errno),
                };
            }
        }
    }

    LowerReadOutcome {
        bytes_read,
        eof: false,
        error: None,
    }
}

fn cache_or_snapshot_page(
    key: PageKey,
    source: &[u8],
    valid_len: usize,
    expected_epoch: Option<u64>,
) -> Result<Option<(Arc<[u8; PAGE_BYTES]>, usize)>, u64> {
    if valid_len > PAGE_BYTES || source.len() < valid_len {
        return Err(crate::syscall::EINVAL);
    }

    let mut cache = PAGE_CACHE.lock();

    if let Some(existing) = cache.iter_mut().find(|entry| entry.key == key) {
        existing.last_used = next_cache_access();

        return Ok(Some((snapshot_page(existing)?, existing.valid_len)));
    }

    let Some(expected_epoch) = expected_epoch else {
        return Ok(None);
    };

    if cache_mutation_epoch() != expected_epoch {
        return Ok(None);
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
            return Ok(None);
        }
    }

    let mut page = [0u8; PAGE_BYTES];

    if valid_len != 0 {
        page[..valid_len].copy_from_slice(&source[..valid_len]);
    }

    let bytes = Arc::new(page);

    cache.push(CachedPage {
        key,
        bytes: bytes.clone(),
        frame_phys: None,
        valid_len,
        dirty_range: None,
        version: 0,
        last_used: next_cache_access(),
    });

    Ok(Some((bytes, valid_len)))
}

fn cache_mutation_epoch() -> u64 {
    PAGE_CACHE_MUTATION_EPOCH.load(Ordering::Acquire)
}

fn bump_cache_mutation_epoch() {
    PAGE_CACHE_MUTATION_EPOCH.fetch_add(1, Ordering::AcqRel);
}
