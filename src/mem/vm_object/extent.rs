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
    _io_guard: super::super::object_io::Reservation,
    // VM-origin preparation retains its provider through publication. An
    // endpoint-owner update retains the canonical gate without fabricating an
    // open description (and therefore without a synthetic OP_RELEASE).
    _provider: Option<Arc<ProviderObject>>,
    old_length: u64,
    old_capacity: u64,
    plan: byte_extent::ResizePlan,
    boundary: Option<Arc<[u8; PAGE_BYTES]>>,
    published: bool,
}

// The entry borrow binds this check to the caller's PAGE_CACHE guard. Never
// retain a Vec index or an entry reference across external work/unlocking.
struct BoundaryCheck<'a> {
    index: usize,
    entry: &'a CachedPage,
    zero_start: usize,
    physical: Option<u64>,
    within: usize,
}

impl VmObject {
    /// Reserve a unique boundary buffer before changing external storage or
    /// mappings. Allocation policy stays with the native coordinator; tests
    /// can inject failure without replacing the production cache algorithm.
    /// The coordinator must hold its mapping/process lock during preparation
    /// so admission checks for new/detached address spaces cannot race it.
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
        PreparedExtent::prepare(
            self.object_key(),
            _io_lock.clone(),
            Some(object.clone()),
            old_length,
            length,
            allocate,
            None,
        )
    }
}

impl PreparedExtent {
    /// Internal provider-owner path. The native caller must first resolve a
    /// RECEIVE capability for this exact endpoint namespace. This does not
    /// fabricate an open description or send a synthetic provider release.
    pub(crate) fn prepare_provider(
        key: ObjectKey,
        old_length: u64,
        length: u64,
        allocate: impl FnOnce([u8; PAGE_BYTES]) -> Result<Arc<[u8; PAGE_BYTES]>, u64>,
    ) -> Result<Self, u64> {
        if !matches!(key, ObjectKey::Provider { identity, .. } if identity != 0) {
            return Err(crate::syscall::EINVAL);
        }
        let gate = PROVIDER_IO
            .lock()
            .try_get(
                key,
                crate::mem::object_io_native::new_lock,
                mnu_abi::status::Error::ResourceUnavailable,
            )
            .map_err(mnu_abi::status::Error::into_raw)?;
        Self::prepare(key, gate, None, old_length, length, allocate, None)
    }

    pub(crate) fn prepare_admitted(
        guard: ProviderIoGuard,
        old_length: u64,
        length: u64,
        allocate: impl FnOnce([u8; PAGE_BYTES]) -> Result<Arc<[u8; PAGE_BYTES]>, u64>,
    ) -> Result<Self, u64> {
        let gate = retain_cache_gate(guard.key)?;
        Self::prepare(
            guard.key,
            gate,
            None,
            old_length,
            length,
            allocate,
            Some(guard._guard),
        )
    }

    fn prepare(
        key: ObjectKey,
        gate: super::super::object_io::IoLock,
        provider: Option<Arc<ProviderObject>>,
        old_length: u64,
        length: u64,
        allocate: impl FnOnce([u8; PAGE_BYTES]) -> Result<Arc<[u8; PAGE_BYTES]>, u64>,
        admitted: Option<super::super::object_io::IoGuard>,
    ) -> Result<Self, u64> {
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
        let io_guard = match admitted {
            Some(guard) => guard,
            None => gate
                .try_lock()
                .map_err(|_| crate::syscall::EIO)?
                .ok_or(crate::syscall::EAGAIN)?,
        };
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
        // Serialize reservation with final PTE installation and cache writes.
        // Allocation failure above must not invalidate any prepared pages.
        let cache = PAGE_CACHE.lock();
        let io_guard = io_guard.reserve();
        let epoch = gate.generation();
        drop(cache);
        Ok(PreparedExtent {
            object: key,
            epoch,
            gate,
            _io_guard: io_guard,
            _provider: provider,
            old_length,
            old_capacity,
            plan,
            boundary,
            published: false,
        })
    }
    /// The VM coordinator must already have suspended ALL mappings and
    /// acknowledged all CPUs, not just the resize-affected subset. Retain
    /// reservation until their records are discarded. No storage is queried.
    pub(crate) fn mark_unavailable(&self) {
        let _cache = PAGE_CACHE.lock();
        self._io_guard.mark_unavailable();
    }

    pub(crate) fn revocation(&self) -> Option<(u64, u64)> {
        self.plan
            .invalidate
            .as_ref()
            .map(|range| (range.start, range.end))
    }

    pub(crate) fn boundary(&self) -> u64 {
        self.old_length.min(self.plan.length)
    }

    /// Validate without changing bytes, dirty ranges, epochs or buffer
    /// ownership. This is not authorization to mutate external storage: the
    /// coordinator still needs storage-outcome/owner-death handling.
    pub(crate) fn preflight(&mut self) -> Result<(), u64> {
        let cache = PAGE_CACHE.lock();
        self.check(&cache).map(|_| ())
    }

    fn check<'a>(&mut self, cache: &'a [CachedPage]) -> Result<Option<BoundaryCheck<'a>>, u64> {
        if self.published {
            return Err(crate::syscall::EINVAL);
        }
        if self.gate.is_unavailable() {
            return Err(crate::syscall::EIO);
        }
        if self.gate.generation() != self.epoch {
            return Err(crate::syscall::EAGAIN);
        }
        let Some(zero) = &self.plan.zero else {
            return Ok(None);
        };
        let Some(index) = cache.iter().position(|entry| {
            entry.key.object == self.object
                && entry.key.page_index == zero.start / PAGE_BYTES as u64
        }) else {
            return Ok(None);
        };
        let entry = &cache[index];
        let boundary = self.boundary.as_mut().ok_or(crate::syscall::EINVAL)?;
        Arc::get_mut(boundary).ok_or(crate::syscall::EINVAL)?;
        let physical = entry
            .frame_phys
            .map(|frame| {
                crate::mem::paging::physical_memory_offset()
                    .and_then(|offset| offset.checked_add(frame))
                    .filter(|start| start.checked_add(PAGE_BYTES as u64 - 1).is_some())
                    .ok_or(crate::syscall::EIO)
            })
            .transpose()?;
        let page_start = entry
            .key
            .page_index
            .checked_mul(PAGE_BYTES as u64)
            .ok_or(crate::syscall::EINVAL)?;
        let within = self
            .plan
            .length
            .checked_sub(page_start)
            .ok_or(crate::syscall::EINVAL)?
            .min(PAGE_BYTES as u64) as usize;
        Ok(Some(BoundaryCheck {
            index,
            entry,
            zero_start: (zero.start % PAGE_BYTES as u64) as usize,
            physical,
            within,
        }))
    }

    /// No IPC or allocation occurs here. All fallible checks precede changes;
    /// a rejected epoch leaves the cache/frame bytes/dirty ranges untouched.
    /// This is only the cache commit, not an external-storage transaction.
    pub(crate) fn commit(mut self) -> Result<(), u64> {
        self.publish()
    }

    /// Publish once without releasing admission. An enclosing journal must
    /// retain this owner until its final PTE restore/release has completed.
    /// Failure retains the reservation too, allowing PTE rollback first.
    /// This is still a fallible local-cache operation, not storage commit.
    pub(crate) fn publish(&mut self) -> Result<(), u64> {
        let mut cache = PAGE_CACHE.lock();
        let checked = self.check(&cache)?;
        if self.plan.length == self.old_length {
            self.published = true;
            return Ok(());
        }
        if let Some(BoundaryCheck {
            index,
            entry,
            zero_start,
            physical,
            within,
        }) = checked
        {
            let boundary = self.boundary.as_mut().ok_or(crate::syscall::EINVAL)?;
            let bytes = Arc::get_mut(boundary).ok_or(crate::syscall::EINVAL)?;
            if let Some(address) = physical {
                for (offset, byte) in bytes.iter_mut().enumerate() {
                    // No Rust references to storage also owned by mappings.
                    *byte =
                        unsafe { core::ptr::read_volatile((address + offset as u64) as *const u8) };
                }
            } else {
                bytes.copy_from_slice(entry.bytes.as_slice());
            }
            bytes[zero_start..].fill(0);
            // Cloning this private Arc cannot allocate. Retain ownership in
            // self too: every failed check above leaves a reusable buffer.
            let replacement = boundary.clone();
            // Every check is complete. PTE suspension/TLB acknowledgement are
            // the caller's exclusion contract, including private COW aliases.
            if let Some(address) = physical {
                for offset in zero_start..PAGE_BYTES {
                    unsafe { core::ptr::write_volatile((address + offset as u64) as *mut u8, 0) };
                }
            }
            let entry = &mut cache[index];
            entry.valid_len = if self.plan.length < self.old_length {
                entry.valid_len.min(within)
            } else {
                within
            };
            entry.dirty_range = entry.dirty_range.and_then(|(start, end)| {
                let end = end.min(entry.valid_len);
                (start < end).then_some((start, end))
            });
            entry.bytes = replacement;
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
        self.published = true;
        Ok(())
    }
}
