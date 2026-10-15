//! Cache-side extent publication. Preparation reserves backing I/O without
//! waiting. The VM coordinator must additionally revoke affected PTEs and
//! acknowledge remote TLBs before calling `commit`.
use super::*;
use crate::mem::byte_extent;

pub(crate) struct PreparedExtent {
    object: ObjectKey,
    epoch: u64,
    gate: super::super::object_io::IoLock,
    // Keep I/O excluded until commit or cancellation, including delayed reply
    // publication by an earlier writer. Never wait in a provider's request path.
    _io_guard: super::super::object_io::IoGuard,
    // Preparation must keep the provider object alive through publication.
    _provider: Arc<ProviderObject>,
    old_length: u64,
    old_capacity: u64,
    plan: byte_extent::ResizePlan,
    boundary: Option<Arc<[u8; PAGE_BYTES]>>,
}

impl VmObject {
    /// Reserve a unique boundary buffer before changing external storage or
    /// mappings. Allocation policy stays with the native coordinator; tests
    /// can inject failure without replacing the production cache algorithm.
    pub(crate) fn prepare_extent(
        &self,
        old_length: u64,
        length: u64,
        allocate: impl FnOnce([u8; PAGE_BYTES]) -> Result<Arc<[u8; PAGE_BYTES]>, u64>,
    ) -> Result<PreparedExtent, u64> {
        let VmObjectSource::Provider {
            object, _io_lock, ..
        } = &self.source
        else {
            return Err(crate::syscall::EINVAL);
        };
        let geometry = |length| {
            byte_extent::plan(
                old_length,
                length,
                PAGE_BYTES as u64,
                u64::MAX / PAGE_BYTES as u64,
            )
            .map_err(|_| crate::syscall::EINVAL)
        };
        let old_capacity = geometry(old_length)?.capacity;
        let plan = geometry(length)?;
        let io_guard = _io_lock.try_lock().ok_or(crate::syscall::EAGAIN)?;
        let epoch = _io_lock.generation();
        let boundary = if plan.zero.is_some() {
            let mut bytes = allocate([0; PAGE_BYTES])?;
            // Nothing may obtain an alias after preparation: the buffer stays
            // private inside this non-Clone transaction until publication.
            if Arc::get_mut(&mut bytes).is_none() {
                return Err(crate::syscall::EINVAL);
            }
            Some(bytes)
        } else {
            None
        };
        Ok(PreparedExtent {
            object: self.object_key(),
            epoch,
            gate: _io_lock.clone(),
            _io_guard: io_guard,
            _provider: object.clone(),
            old_length,
            old_capacity,
            plan,
            boundary,
        })
    }
}

impl PreparedExtent {
    /// No IPC or allocation occurs here. All fallible checks precede changes;
    /// a rejected epoch leaves the cache/frame bytes/dirty ranges untouched.
    /// This is only the cache commit, not an external-storage transaction.
    pub(crate) fn commit(mut self) -> Result<(), u64> {
        let mut cache = PAGE_CACHE.lock();
        if self.gate.generation() != self.epoch {
            return Err(crate::syscall::EAGAIN);
        }
        if self.plan.length == self.old_length {
            return Ok(());
        }
        let boundary_index = self.plan.zero.as_ref().and_then(|range| {
            cache.iter().position(|entry| {
                entry.key.object == self.object
                    && entry.key.page_index == range.start / PAGE_BYTES as u64
            })
        });
        if let Some(index) = boundary_index {
            let entry = &cache[index];
            let zero = self.plan.zero.as_ref().ok_or(crate::syscall::EINVAL)?;
            let zero_start = (zero.start % PAGE_BYTES as u64) as usize;
            let mut boundary = self.boundary.take().ok_or(crate::syscall::EINVAL)?;
            let bytes = Arc::get_mut(&mut boundary).ok_or(crate::syscall::EINVAL)?;
            let physical = match entry.frame_phys {
                Some(frame) => {
                    let address = crate::mem::paging::physical_memory_offset()
                        .and_then(|offset| offset.checked_add(frame))
                        .filter(|start| start.checked_add(PAGE_BYTES as u64 - 1).is_some())
                        .ok_or(crate::syscall::EIO)?;
                    for (offset, byte) in bytes.iter_mut().enumerate() {
                        // No Rust references to storage also owned by mappings.
                        *byte = unsafe {
                            core::ptr::read_volatile((address + offset as u64) as *const u8)
                        };
                    }
                    Some(address)
                }
                None => {
                    bytes.copy_from_slice(entry.bytes.as_slice());
                    None
                }
            };
            bytes[zero_start..].fill(0);
            // Every check is complete. PTE suspension/TLB acknowledgement are
            // the caller's exclusion contract, including private COW aliases.
            if let Some(address) = physical {
                for offset in zero_start..PAGE_BYTES {
                    unsafe { core::ptr::write_volatile((address + offset as u64) as *mut u8, 0) };
                }
            }
            let entry = &mut cache[index];
            let within = (self.plan.length - entry.key.page_index * PAGE_BYTES as u64)
                .min(PAGE_BYTES as u64) as usize;
            entry.valid_len = if self.plan.length < self.old_length {
                entry.valid_len.min(within)
            } else {
                within
            };
            entry.dirty_range = entry.dirty_range.and_then(|(start, end)| {
                let end = end.min(entry.valid_len);
                (start < end).then_some((start, end))
            });
            entry.bytes = boundary;
            entry.version = entry.version.wrapping_add(1);
        }
        // Growth must discard negative EOF cache entries too; otherwise newly
        // present storage could remain permanently reported as outside backing.
        let keep_below = if self.plan.length < self.old_length {
            self.plan.capacity
        } else {
            self.old_capacity
        };
        cache.retain(|entry| {
            entry.key.object != self.object || entry.key.page_index < keep_below / PAGE_BYTES as u64
        });
        bump_cache_mutation_epoch(self.object);
        Ok(())
    }
}
