//! VM objects and a bounded object page cache.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::interrupt::spinlock::SpinLock;
use crate::task::ProviderObject;

pub const PAGE_BYTES: usize = 4096;

/// A failed fault-page preparation, distinct from an ordinary read at EOF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmPageError {
    OutsideBacking,
    Operation(u64),
}

impl From<u64> for VmPageError {
    fn from(error: u64) -> Self {
        Self::Operation(error)
    }
}

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
enum ObjectKey {
    Memory(u64),
    Provider {
        endpoint_thread_id: u64,
        endpoint_slot: u16,
        endpoint_generation: u64,
        identity: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PageKey {
    object: ObjectKey,
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
static PROVIDER_IO: SpinLock<super::object_io::Registry<ObjectKey>> =
    SpinLock::new(super::object_io::Registry::new());

#[derive(Clone)]
pub struct VmObject {
    source: VmObjectSource,
}

/// Pins a cache frame while a fault resolves its backing outside task locks.
pub struct PreparedSharedPage {
    frame_phys: u64,
    memory_generation: Option<(Arc<super::shared_memory::SharedMemory>, u64)>,
}

impl PreparedSharedPage {
    pub fn map_to(
        &self,
        table_phys: u64,
        virt_addr: u64,
        writable: bool,
        executable: bool,
    ) -> Result<(), u64> {
        let install = || {
            crate::mem::paging::map_shared_frame_to_user(
                table_phys, virt_addr, self.frame_phys, writable, executable,
            )
            .map_err(|_| crate::syscall::ENOMEM)
        };
        match &self.memory_generation {
            Some((memory, generation)) => memory.with_generation(*generation, install),
            None => install(),
        }
    }
}

impl Drop for PreparedSharedPage {
    fn drop(&mut self) {
        crate::mem::paging::release_user_frame(self.frame_phys);
    }
}

#[derive(Clone)]
enum VmObjectSource {
    Memory(Arc<super::shared_memory::SharedMemory>),
    Provider {
        object: Arc<ProviderObject>,
        identity: u64,
    },
}

impl VmObject {
    pub fn shared_memory(memory: Arc<super::shared_memory::SharedMemory>) -> Self {
        Self {
            source: VmObjectSource::Memory(memory),
        }
    }

    pub fn memory_length(&self) -> Option<u64> {
        match &self.source {
            VmObjectSource::Memory(memory) => Some(memory.length()),
            _ => None,
        }
    }

    pub(crate) fn resize_memory(&self, length: u64) -> Result<(), u64> {
        match &self.source {
            VmObjectSource::Memory(memory) => {
                crate::task::process::resize_shared_memory(memory, length)
            }
            _ => Err(crate::syscall::EINVAL),
        }
    }

    pub(crate) fn memory_identity(&self) -> Option<u64> {
        match &self.source {
            VmObjectSource::Memory(memory) => Some(memory.id()),
            _ => None,
        }
    }

    pub(crate) fn memory_generation(&self) -> Option<u64> {
        match &self.source {
            VmObjectSource::Memory(memory) => Some(memory.generation()),
            _ => None,
        }
    }

    /// Validate a snapshot taken before loading private page bytes, and keep
    /// RAM backing stable throughout the final PTE installation.
    pub(crate) fn with_memory_generation<T>(
        &self,
        generation: Option<u64>,
        install: impl FnOnce() -> Result<T, u64>,
    ) -> Result<T, u64> {
        match (&self.source, generation) {
            (VmObjectSource::Memory(memory), Some(generation)) => {
                memory.with_generation(generation, install)
            }
            (VmObjectSource::Provider { .. }, None) => install(),
            _ => Err(crate::syscall::EINVAL),
        }
    }

    pub fn provider(object: Arc<ProviderObject>, identity: u64) -> Self {
        Self {
            source: VmObjectSource::Provider { object, identity },
        }
    }

    fn object_key(&self) -> ObjectKey {
        match &self.source {
            VmObjectSource::Memory(memory) => ObjectKey::Memory(memory.id()),
            VmObjectSource::Provider { object, identity } => ObjectKey::Provider {
                endpoint_thread_id: object.endpoint_thread_id,
                endpoint_slot: object.endpoint_slot,
                endpoint_generation: object.endpoint_generation,
                identity: *identity,
            },
        }
    }

    fn page_key(&self, page_index: u64) -> PageKey {
        PageKey {
            object: self.object_key(),
            page_index,
        }
    }

    pub fn page(&self, page_index: u64) -> Result<Arc<[u8; PAGE_BYTES]>, VmPageError> {
        self.fault_page_with_len(page_index).map(|(bytes, _)| bytes)
    }

    fn page_error(&self, error: u64) -> VmPageError {
        // RAM population uses EINVAL only for an index outside its extent.
        // A provider's error with the same value must not be guessed as EOF.
        match (&self.source, error) {
            (VmObjectSource::Memory(_), crate::syscall::EINVAL) => VmPageError::OutsideBacking,
            _ => VmPageError::Operation(error),
        }
    }

    fn fault_page_with_len(
        &self,
        page_index: u64,
    ) -> Result<(Arc<[u8; PAGE_BYTES]>, usize), VmPageError> {
        let (bytes, valid_len) = self
            .page_with_len(page_index)
            .map_err(|error| self.page_error(error))?;
        if valid_len == 0 {
            return Err(VmPageError::OutsideBacking);
        }
        // A partial final page remains accessible with its zero-filled tail.
        Ok((bytes, valid_len))
    }

    fn page_with_len(&self, page_index: u64) -> Result<(Arc<[u8; PAGE_BYTES]>, usize), u64> {
        if let VmObjectSource::Memory(memory) = &self.source {
            let offset = page_index
                .checked_mul(PAGE_BYTES as u64)
                .ok_or(crate::syscall::EINVAL)?;
            // Ordinary read_at may return EOF, but a pager must not manufacture
            // an accessible zero-filled private page beyond its RAM extent.
            if offset >= memory.length() {
                return Err(crate::syscall::EINVAL);
            }
            let mut bytes = [0u8; PAGE_BYTES];
            let length = memory.read_at(offset, &mut bytes)?;
            return Ok((Arc::new(bytes), length));
        }
        let key = self.page_key(page_index);

        if let Some(page) = cached_page(key)? {
            return Ok(page);
        }

        let offset = page_index
            .checked_mul(PAGE_BYTES as u64)
            .ok_or(crate::syscall::EINVAL)?;

        let epoch = cache_mutation_epoch();
        let mut page = [0u8; PAGE_BYTES];
        let outcome = read_lower_until(&self.source, offset, &mut page);

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
        invalidate_object(self.object_key());
    }

    pub fn read_at(&self, offset: u64, output: &mut [u8]) -> Result<usize, u64> {
        if let VmObjectSource::Memory(memory) = &self.source {
            return memory.read_at(offset, output);
        }
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
        let input_len = u64::try_from(input.len()).map_err(|_| crate::syscall::EINVAL)?;

        offset
            .checked_add(input_len)
            .ok_or(crate::syscall::EINVAL)?;

        let _io_guard = if matches!(&self.source, VmObjectSource::Provider { .. }) {
            Some(lock_provider_key(self.object_key()))
        } else {
            None
        };
        let written = write_lower(&self.source, offset, input)?;

        if written > input.len() {
            return Err(crate::syscall::EIO);
        }

        update_cached_range(self.object_key(), offset, &input[..written]);

        Ok(written)
    }

    pub fn prepare_shared_page(&self, page_index: u64) -> Result<PreparedSharedPage, VmPageError> {
        if let VmObjectSource::Memory(memory) = &self.source {
            let (frame_phys, generation) = memory
                .prepare_page(page_index)
                .map_err(|error| self.page_error(error))?;
            return Ok(PreparedSharedPage {
                frame_phys,
                memory_generation: Some((memory.clone(), generation)),
            });
        }
        let (loaded, loaded_len) = self.fault_page_with_len(page_index)?;
        let key = self.page_key(page_index);

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
                return Err(VmPageError::Operation(errno));
            }
            cache[entry_index].frame_phys = Some(frame_phys);
        }
        let frame_phys = cache[entry_index]
            .frame_phys
            .ok_or(crate::syscall::ENOMEM)?;
        crate::mem::paging::retain_shared_user_frame(frame_phys)
            .map_err(|_| crate::syscall::ENOMEM)?;
        cache[entry_index].last_used = next_cache_access();
        Ok(PreparedSharedPage {
            frame_phys,
            memory_generation: None,
        })
    }

    pub fn mark_page_dirty(&self, page_index: u64) -> Result<(), u64> {
        if let VmObjectSource::Memory(memory) = &self.source {
            return if page_index
                .checked_mul(PAGE_BYTES as u64)
                .is_some_and(|offset| offset < memory.length())
            {
                Ok(())
            } else {
                Err(crate::syscall::EINVAL)
            };
        }
        let key = self.page_key(page_index);

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
        if let VmObjectSource::Memory(memory) = &self.source {
            return memory.write_at(offset, input);
        }
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

            let key = self.page_key(page_index);

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

    /// Writes dirty cache pages intersecting the range back to their object.
    pub fn flush_range(&self, offset: u64, length: u64) -> Result<(), u64> {
        if let VmObjectSource::Memory(_) = &self.source {
            // RAM stores are already visible to aliases; there is no lower
            // writeback target. Reservations can exceed the live extent, and
            // shrink must not make their eventual unmap/sync fail.
            return if length == u64::MAX && offset == 0 || offset.checked_add(length).is_some() {
                Ok(())
            } else {
                Err(crate::syscall::EINVAL)
            };
        }
        if length == 0 {
            return Ok(());
        }
        // Retain ordering through the lower write and cache update. The
        // registry lock is released before waiting or calling provider IPC.
        let _io_guard = if matches!(self.source, VmObjectSource::Provider { .. }) {
            Some(lock_provider_key(self.object_key()))
        } else {
            None
        };
        let range_end = offset.saturating_add(length);
        let snapshots = {
            let mut cache = PAGE_CACHE.lock();
            let mut snapshots = Vec::new();
            let object_key = self.object_key();
            for entry in cache
                .iter_mut()
                .filter(|entry| entry.key.object == object_key)
            {
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
            let written = write_lower(&self.source, write_offset, &bytes[dirty_start..dirty_end])?;
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
        if let VmObjectSource::Provider { object, .. } = &self.source {
            crate::syscall::handle::provider_sync(object)?;
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
            .field("source", &self.object_key())
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

pub(crate) fn update_provider_range(
    object: &ProviderObject,
    identity: u64,
    offset: u64,
    input: &[u8],
) {
    update_cached_range(
        ObjectKey::Provider {
            endpoint_thread_id: object.endpoint_thread_id,
            endpoint_slot: object.endpoint_slot,
            endpoint_generation: object.endpoint_generation,
            identity,
        },
        offset,
        input,
    );
}

pub(crate) fn lock_provider_io(object: &ProviderObject, identity: u64) -> super::object_io::IoGuard {
    lock_provider_key(ObjectKey::Provider {
        endpoint_thread_id: object.endpoint_thread_id,
        endpoint_slot: object.endpoint_slot,
        endpoint_generation: object.endpoint_generation,
        identity,
    })
}

/// Overlays resident backing bytes without loading a page or making IPC calls.
pub(crate) fn overlay_provider_range(
    object: &ProviderObject,
    identity: u64,
    offset: u64,
    output: &mut [u8],
) -> Result<(), u64> {
    let end = offset
        .checked_add(output.len() as u64)
        .ok_or(crate::syscall::EIO)?;
    let key = ObjectKey::Provider {
        endpoint_thread_id: object.endpoint_thread_id,
        endpoint_slot: object.endpoint_slot,
        endpoint_generation: object.endpoint_generation,
        identity,
    };
    let mut cache = PAGE_CACHE.lock();
    for entry in cache.iter_mut().filter(|entry| entry.key.object == key) {
        let page_start = entry
            .key
            .page_index
            .checked_mul(PAGE_BYTES as u64)
            .ok_or(crate::syscall::EIO)?;
        let page_end = page_start
            .checked_add(entry.valid_len as u64)
            .ok_or(crate::syscall::EIO)?;
        if page_start >= end || page_end <= offset {
            continue;
        }
        let bytes = snapshot_page(entry)?;
        super::cache_range::copy_overlap(offset, output, page_start, &bytes[..entry.valid_len])
            .map_err(|_| crate::syscall::EIO)?;
        entry.last_used = next_cache_access();
    }
    Ok(())
}

fn lock_provider_key(key: ObjectKey) -> super::object_io::IoGuard {
    let gate = PROVIDER_IO.lock().get(key);
    gate.lock(|| {
        let _ = crate::task::yield_now();
    })
}

fn invalidate_object(object: ObjectKey) {
    let mut cache = PAGE_CACHE.lock();

    cache.retain(|entry| {
        entry.key.object != object
            || entry
                .frame_phys
                .is_some_and(crate::mem::paging::user_frame_has_multiple_owners)
    });

    bump_cache_mutation_epoch();
}

fn update_cached_range(object: ObjectKey, offset: u64, input: &[u8]) {
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
        .filter(|entry| entry.key.object == object)
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

fn read_lower_until(source: &VmObjectSource, offset: u64, output: &mut [u8]) -> LowerReadOutcome {
    let mut bytes_read = 0usize;
    let io_limit = match source {
        VmObjectSource::Memory(_) => PAGE_BYTES,
        VmObjectSource::Provider { .. } => mnu_abi::provider::MAX_DATA_LEN,
    };

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

        let read = match source {
            VmObjectSource::Memory(memory) => {
                memory.read_at(current, &mut output[bytes_read..bytes_read + request_len])
            }
            VmObjectSource::Provider { object, .. } => crate::syscall::handle::provider_read_at(
                object,
                current,
                &mut output[bytes_read..bytes_read + request_len],
            ),
        };
        match read {
            Ok(0) => {
                return LowerReadOutcome {
                    bytes_read,
                    eof: true,
                    error: None,
                };
            }

            Ok(read) if read <= request_len => {
                bytes_read += read;
                if read < request_len {
                    return LowerReadOutcome {
                        bytes_read,
                        eof: true,
                        error: None,
                    };
                }
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

fn write_lower(source: &VmObjectSource, offset: u64, input: &[u8]) -> Result<usize, u64> {
    match source {
        VmObjectSource::Memory(memory) => memory.write_at(offset, input),
        VmObjectSource::Provider { object, .. } => {
            crate::syscall::handle::provider_write_at(object, offset, input)
        }
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
