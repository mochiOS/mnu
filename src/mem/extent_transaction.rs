//! Owned VM backing publication and mapping cleanup. VM exclusion is retained
//! only during PTE/metadata work. Extent mutation requires full suspension and
//! an explicit external-storage outcome; losing an in-flight owner quarantines
//! its backing. Cache refresh performs admitted writeback outside VM exclusion
//! and can roll back its dirty mappings if that writeback fails.
use super::{
    mapping_targets::Targets,
    paging, tlb_shootdown,
    vm_object::{ObjectKey, PreparedExtent, PreparedRefresh, VmObject},
};
use crate::interrupt::spinlock::SpinLock;
use crate::task::{
    deferred::{Deferred, Pending, Ticket},
    process,
};
use alloc::{sync::Arc, vec::Vec};
use mnu_abi::status::Error;

struct Page {
    record: paging::RecordedUserPage,
    zero: Option<(u64, usize)>,
    affected: bool,
}

struct Work {
    pages: Vec<Page>,
    // Field order keeps root lifetime and backing admission until all records
    // have been resolved. Incomplete Work is never dropped by this module.
    targets: Targets,
    extent: PreparedBacking,
    publication: Publication,
    external: bool,
}

// The journal owns both kinds through the same root/PTE cleanup path. Cache
// refresh writes existing bytes only; unlike an extent mutation, a failed
// writeback can safely restore its original dirty mappings.
enum PreparedBacking {
    Extent(PreparedExtent),
    Refresh(PreparedRefresh),
}

impl PreparedBacking {
    fn is_refresh(&self) -> bool {
        matches!(self, Self::Refresh(_))
    }
    fn revocation(&self) -> Option<(u64, u64)> {
        match self {
            Self::Extent(owner) => owner.revocation(),
            Self::Refresh(owner) => Some(owner.range()),
        }
    }
    fn boundary(&self) -> u64 {
        match self {
            Self::Extent(owner) => owner.boundary(),
            Self::Refresh(_) => 0,
        }
    }
    fn preflight(&mut self) -> Result<(), u64> {
        match self {
            Self::Extent(owner) => owner.preflight(),
            Self::Refresh(owner) => owner.preflight(),
        }
    }
    fn publish(&mut self) -> Result<(), u64> {
        match self {
            Self::Extent(owner) => owner.publish(),
            Self::Refresh(owner) => owner.publish(),
        }
    }
    fn mark_unavailable(&self) -> Result<(), u64> {
        match self {
            Self::Extent(owner) => {
                owner.mark_unavailable();
                Ok(())
            }
            Self::Refresh(_) => Err(Error::InvalidArgument.into_raw()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Publication {
    Prepared,
    InFlight,
    Unchanged,
    Unavailable,
    Requested,
    Published,
}

static PENDING: SpinLock<Pending<Option<Work>>> = SpinLock::new(Pending::new());

#[must_use = "drop schedules cancellation or completion without taking the VM lock"]
pub(crate) struct ExtentTransaction {
    owner: Option<Deferred<'static, Option<Work>>>,
}

impl ExtentTransaction {
    /// Internal cache refresh only. Resource authority must already have been
    /// checked by its VM caller. No user addresses survive this preparation.
    pub(crate) fn prepare_refresh(object: &VmObject, start: u64, length: u64) -> Result<Self, u64> {
        Self::prepare_backing(object.object_key(), false, || {
            object.prepare_refresh(start, length).map(PreparedBacking::Refresh)
        })
    }

    /// The journal has already suspended shared aliases and acknowledged every
    /// CPU. Keep its root pins and backing reservation, but release VM exclusion
    /// during lower I/O. Failure leaves dirty cache and rollback ownership.
    pub(crate) fn writeback_refresh(&mut self) -> Result<(), u64> {
        let owner = self.owner.as_mut().ok_or(Error::InvalidArgument.into_raw())?;
        let work = owner.value_mut().as_mut().ok_or(Error::InvalidArgument.into_raw())?;
        if work.external || work.publication != Publication::Prepared || !work.extent.is_refresh() {
            return Err(Error::InvalidArgument.into_raw());
        }
        process::with_mapping_table(|_| {
            if work.pages.iter().all(|page| work.current(page)) {
                Ok(())
            } else {
                Err(Error::BackingFailure.into_raw())
            }
        })?;
        match &mut work.extent {
            PreparedBacking::Refresh(refresh) => refresh.writeback(),
            PreparedBacking::Extent(_) => Err(Error::InvalidArgument.into_raw()),
        }
    }

    /// Internal coordinator only; no caller authority is inferred from a PID,
    /// file path, or provider identity. Outward-facing entries must validate
    /// resource-control authority before reaching a constructor.
    pub(crate) fn prepare(object: &VmObject, old_length: u64, length: u64) -> Result<Self, u64> {
        Self::prepare_with_scope(object, old_length, length, false)
    }

    /// Suspend every mapping, including unaffected prefixes, before external
    /// work can begin. Dropping before begin_external still cancels normally.
    /// This internal VM-object entry grants no outward-facing authority.
    pub(crate) fn prepare_external(
        object: &VmObject,
        old_length: u64,
        length: u64,
    ) -> Result<Self, u64> {
        Self::prepare_with_scope(object, old_length, length, true)
    }

    fn prepare_with_scope(
        object: &VmObject,
        old_length: u64,
        length: u64,
        external: bool,
    ) -> Result<Self, u64> {
        Self::prepare_extent(object.object_key(), external, || {
            object.prepare_extent(old_length, length, |bytes| {
                Arc::try_new(bytes).map_err(|_| Error::ResourceUnavailable.into_raw())
            })
        })
    }

    /// Called only after validating the endpoint owner's RECEIVE Handle.
    /// An object identity alone, even a known one, grants no update authority.
    pub(crate) fn prepare_provider(
        key: ObjectKey,
        old_length: u64,
        length: u64,
    ) -> Result<Self, u64> {
        Self::prepare_extent(key, true, || {
            PreparedExtent::prepare_provider(key, old_length, length, |bytes| {
                Arc::try_new(bytes).map_err(|_| Error::ResourceUnavailable.into_raw())
            })
        })
    }

    pub(crate) fn prepare_admitted(
        guard: super::vm_object::ProviderIoGuard,
        old_length: u64,
        length: u64,
    ) -> Result<Self, u64> {
        Self::prepare_extent(guard.key(), true, || {
            PreparedExtent::prepare_admitted(guard, old_length, length, |bytes| {
                Arc::try_new(bytes).map_err(|_| Error::ResourceUnavailable.into_raw())
            })
        })
    }

    fn prepare_extent(
        key: ObjectKey,
        external: bool,
        prepare: impl FnOnce() -> Result<PreparedExtent, u64>,
    ) -> Result<Self, u64> {
        Self::prepare_backing(key, external, || prepare().map(PreparedBacking::Extent))
    }

    fn prepare_backing(
        key: ObjectKey,
        external: bool,
        prepare: impl FnOnce() -> Result<PreparedBacking, u64>,
    ) -> Result<Self, u64> {
        // Reserve cancellation storage BEFORE edits, including failed prepare.
        let ticket = Ticket::new(None).map_err(|_| Error::ResourceUnavailable.into_raw())?;
        let mut owner = ticket.defer_on_drop(&PENDING);
        process::with_mapping_table(|table| {
            let extent = prepare()?;
            let (start, end) = extent.revocation().unwrap_or((0, 0));
            let affected = external
                .then(|| Targets::capture(table, key, start, end, extent.boundary()))
                .transpose()
                .map_err(mnu_abi::status::Error::into_raw)?;
            let (low, high) = if external {
                (0, u64::MAX & !4095)
            } else {
                (start, end)
            };
            let targets = if extent.is_refresh() {
                Targets::capture_shared(table, key, low, high)
            } else {
                Targets::capture(table, key, low, high, extent.boundary())
            }.map_err(mnu_abi::status::Error::into_raw)?;
            let mut locations = Vec::new();
            for (root, start, end) in targets.ranges() {
                let mut cursor = start;
                while cursor < end {
                    // SAFETY: capture retained every root; VM exclusion and the
                    // backing reservation exclude all selected PTE writers.
                    let Some(address) =
                        (unsafe { paging::next_user_page_entry(root, cursor, end) })
                            .map_err(|_| Error::BackingFailure.into_raw())?
                    else {
                        break;
                    };
                    if address < cursor || address >= end || address & 4095 != 0 {
                        return Err(Error::BackingFailure.into_raw());
                    }
                    locations
                        .try_reserve(1)
                        .map_err(|_| Error::ResourceUnavailable.into_raw())?;
                    let changed = affected
                        .as_ref()
                        .is_none_or(|targets| targets.contains(root, address, address + 4096));
                    locations.push((root, address, changed));
                    cursor = address + 4096;
                }
            }
            let mut pages = Vec::new();
            pages
                .try_reserve_exact(locations.len())
                .map_err(|_| Error::ResourceUnavailable.into_raw())?;
            *owner.value_mut() = Some(Work {
                pages,
                targets,
                extent,
                publication: Publication::Prepared,
                external,
            });
            let work = owner.value_mut().as_mut().ok_or(Error::InvalidArgument.into_raw())?;
            for (root, address, affected) in locations {
                // SAFETY: same retained roots, reservation and VM exclusion.
                if let Some(page) = unsafe { paging::suspend_user_page(root, address) }
                    .map_err(|_| Error::BackingFailure.into_raw())?
                {
                    work.pages.push(Page {
                        record: page.into_record(),
                        zero: None,
                        affected,
                    });
                    // Publish the record into the cancellation owner BEFORE
                    // any later check can fail. Push cannot allocate here.
                    let page = work.pages.last_mut().ok_or(Error::InvalidArgument.into_raw())?;
                    if let Some(boundary) = work.targets.preserved().iter().find(|boundary| {
                        affected && boundary.table == root && boundary.address == address
                    }) {
                        page.zero = Some(
                            page.record
                                .suffix_address(boundary.zero_from)
                                .map_err(|_| Error::BackingFailure.into_raw())?,
                        );
                    }
                }
            }
            if !work.pages.is_empty() {
                tlb_shootdown::invalidate_all().map_err(|_| Error::BackingFailure.into_raw())?;
            }
            // Surface cache-address/buffer errors before handing back an
            // unlocked owner. No external-storage permission is implied.
            work.extent.preflight()?;
            Ok::<_, u64>(())
        })?;
        Ok(Self { owner: Some(owner) })
    }

    /// Record the uncertainty boundary BEFORE issuing external mutation. No
    /// VM lock is held over that mutation. Once begun, owner loss cannot mean
    /// cancellation: cleanup must discard all suspended mappings instead.
    pub(crate) fn begin_external(&mut self) -> Result<(), u64> {
        let owner = self.owner.as_mut().ok_or(Error::InvalidArgument.into_raw())?;
        process::with_mapping_table(|_| {
            let work = owner.value_mut().as_mut().ok_or(Error::InvalidArgument.into_raw())?;
            if !work.external || work.publication != Publication::Prepared {
                return Err(Error::InvalidArgument.into_raw());
            }
            if !work.pages.iter().all(|page| work.current(page)) {
                return Err(Error::BackingFailure.into_raw());
            }
            work.extent.preflight()?;
            work.publication = Publication::InFlight;
            Ok(())
        })
    }

    /// The resource owner confirms storage is unchanged, not merely that an
    /// I/O request returned an error. Keep that decision across cleanup retry.
    pub(crate) fn confirm_unchanged(&mut self) -> Result<(), u64> {
        let owner = self.owner.as_mut().ok_or(Error::InvalidArgument.into_raw())?;
        process::with_mapping_table(|_| {
            let work = owner.value_mut().as_mut().ok_or(Error::InvalidArgument.into_raw())?;
            if !matches!(
                work.publication,
                Publication::InFlight | Publication::Unchanged
            ) {
                return Err(Error::InvalidArgument.into_raw());
            }
            work.publication = Publication::Unchanged;
            work.resolve()
        })?;
        self.release_completed();
        Ok(())
    }

    /// Fallible LOCAL publication only. The owner retains admission on every
    /// error. Once cache publication succeeds, drop/retry always completes the
    /// new extent rather than restoring removed mappings to the old extent.
    pub(crate) fn publish_local(&mut self) -> Result<(), u64> {
        self.finish(false)
    }

    /// Record an irrevocable decision to publish this extent BEFORE any
    /// remaining cache/PTE check can fail. Subsequent failure or owner drop
    /// retries publication; it must never restore the old extent.
    /// This neither starts nor acknowledges external I/O. Its outcome must
    /// already be resolved by the caller. Native update Handles instead use
    /// request_external_publication after authenticated owner preparation.
    pub(crate) fn request_publication(&mut self) -> Result<(), u64> {
        self.finish(true)
    }

    /// Provider-owned update Handles must cross the uncertainty boundary
    /// explicitly; the local-only publication API cannot substitute for BEGIN.
    pub(crate) fn request_external_publication(&mut self) -> Result<(), u64> {
        let owner = self.owner.as_mut().ok_or(Error::InvalidArgument.into_raw())?;
        let work = owner.value_mut().as_ref().ok_or(Error::InvalidArgument.into_raw())?;
        if !work.external
            || !matches!(
                work.publication,
                Publication::InFlight | Publication::Requested | Publication::Published
            )
        {
            return Err(Error::InvalidArgument.into_raw());
        }
        self.finish(true)
    }

    fn finish(&mut self, request_publication: bool) -> Result<(), u64> {
        let owner = self.owner.as_mut().ok_or(Error::InvalidArgument.into_raw())?;
        process::with_mapping_table(|_| {
            let work = owner.value_mut().as_mut().ok_or(Error::InvalidArgument.into_raw())?;
            if request_publication && work.extent.is_refresh() {
                return Err(Error::InvalidArgument.into_raw());
            }
            if work.publication == Publication::Unchanged {
                return Err(Error::InvalidArgument.into_raw());
            }
            if work.publication == Publication::InFlight && !request_publication {
                return Err(Error::InvalidArgument.into_raw());
            }
            if work.publication == Publication::Unavailable {
                return Err(Error::BackingFailure.into_raw());
            }
            if request_publication
                && matches!(
                    work.publication,
                    Publication::Prepared | Publication::InFlight
                )
            {
                work.publication = Publication::Requested;
            }
            work.publish_cache()?;
            work.resolve()
        })?;
        self.release_completed();
        Ok(())
    }

    fn release_completed(&mut self) {
        // Every PTE is finished. Disarm enqueue and release pins/admission
        // outside the VM lock; root/provider destruction can run other cleanup.
        if let Some(owner) = self.owner.take() {
            drop(owner.into_ticket());
        }
    }
}

impl Work {
    fn publish_cache(&mut self) -> Result<(), u64> {
        if self.publication != Publication::Published {
            // All PTE checks precede cache mutation, under the same lock.
            if !self.pages.iter().all(|page| self.current(page)) {
                return Err(Error::BackingFailure.into_raw());
            }
            self.extent.publish()?;
            self.publication = Publication::Published;
        }
        Ok(())
    }

    fn progress(&mut self) -> Result<(), u64> {
        match self.publication {
            Publication::InFlight => {
                // Only external/full-suspension preparation can enter this
                // phase, after successful all-CPU TLB acknowledgement.
                self.extent.mark_unavailable()?;
                self.publication = Publication::Unavailable;
                self.resolve()
            }
            Publication::Prepared | Publication::Unchanged | Publication::Unavailable => {
                self.resolve()
            }
            Publication::Requested | Publication::Published => {
                self.publish_cache()?;
                self.resolve()
            }
        }
    }

    // Caller holds VM exclusion; the reservation/root pins remain owned here.
    fn current(&self, page: &Page) -> bool {
        let (root, address) = page.record.location();
        address.checked_add(4096).is_some_and(|end| self.targets.contains(root, address, end))
            // SAFETY: the enclosing VM lock, selected roots and reservation.
            && unsafe { page.record.is_current() }
    }

    fn resolve(&mut self) -> Result<(), u64> {
        let published = match self.publication {
            Publication::Prepared | Publication::Unchanged | Publication::Unavailable => false,
            Publication::Published => true,
            // Neither an uncertain outcome nor an irrevocable request may
            // fall through to cancellation.
            Publication::InFlight | Publication::Requested => return Err(Error::NotReady.into_raw()),
        };
        while let Some(page) = self.pages.pop() {
            if !self.current(&page) {
                self.pages.push(page);
                return Err(Error::BackingFailure.into_raw());
            }
            // Zero only after cache publication, never during cancellation.
            // Physical access was validated before TLB synchronization.
            if published {
                if let Some((start, length)) = page.zero {
                    for offset in 0..length {
                        unsafe {
                            core::ptr::write_volatile((start + offset as u64) as *mut u8, 0);
                        }
                    }
                }
            }
            let Page {
                record,
                zero,
                affected,
            } = page;
            // SAFETY: selected root is pinned, VM exclusion is held, and
            // published release is reachable only after all-CPU TLB ack.
            let result = unsafe {
                if self.publication != Publication::Unavailable
                    && (!published || !affected || zero.is_some())
                {
                    record.try_restore()
                } else {
                    record.try_release()
                }
            };
            if let Err(record) = result {
                self.pages.push(Page {
                    record,
                    zero,
                    affected,
                });
                return Err(Error::BackingFailure.into_raw());
            }
        }
        Ok(())
    }
}

/// Detach first; never hold queue exclusion while entering VM or destroying
/// payloads. A busy VM lock or rejected PTE keeps its original reserved ticket
/// for a later pass, including when called from an already-locked context.
pub(crate) fn flush() {
    let mut batch = {
        let mut pending = PENDING.lock();
        core::mem::take(&mut *pending)
    }
    .reversed();
    while let Some(mut ticket) = batch.pop() {
        let complete = match ticket.value_mut().as_mut() {
            None => true,
            Some(work) => process::try_with_mapping_table(|_| work.progress())
                .is_some_and(|result| result.is_ok()),
        };
        if !complete {
            PENDING.lock().push(ticket);
        }
        // Complete ticket/payload drop occurs after the VM guard was released.
    }
}
