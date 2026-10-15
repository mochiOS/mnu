//! Native, owned mapping/cache extent coordination. No VM lock is retained by
//! the owner. External I/O requires full suspension before begin_external,
//! followed by an explicit unchanged/publication outcome. Losing an in-flight
//! owner quarantines the backing; this module does not perform storage I/O.
use super::{
    mapping_targets::Targets,
    paging, tlb_shootdown,
    vm_object::{ObjectKey, PreparedExtent, VmObject},
};
use crate::interrupt::spinlock::SpinLock;
use crate::task::{
    deferred::{Deferred, Pending, Ticket},
    process,
};
use alloc::{sync::Arc, vec::Vec};

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
    extent: PreparedExtent,
    publication: Publication,
    external: bool,
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
                Arc::try_new(bytes).map_err(|_| crate::syscall::ENOMEM)
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
                Arc::try_new(bytes).map_err(|_| crate::syscall::ENOMEM)
            })
        })
    }

    fn prepare_extent(
        key: ObjectKey,
        external: bool,
        prepare: impl FnOnce() -> Result<PreparedExtent, u64>,
    ) -> Result<Self, u64> {
        // Reserve cancellation storage BEFORE edits, including failed prepare.
        let ticket = Ticket::new(None).map_err(|_| crate::syscall::ENOMEM)?;
        let mut owner = ticket.defer_on_drop(&PENDING);
        process::with_mapping_table(|table| {
            let extent = prepare()?;
            let (start, end) = extent.revocation().unwrap_or((0, 0));
            let affected = external
                .then(|| Targets::capture(table, key, start, end, extent.boundary()))
                .transpose()?;
            let (low, high) = if external {
                (0, u64::MAX & !4095)
            } else {
                (start, end)
            };
            let targets = Targets::capture(table, key, low, high, extent.boundary())?;
            let mut locations = Vec::new();
            for (root, start, end) in targets.ranges() {
                let mut cursor = start;
                while cursor < end {
                    // SAFETY: capture retained every root; VM exclusion and the
                    // backing reservation exclude all selected PTE writers.
                    let Some(address) =
                        (unsafe { paging::next_user_page_entry(root, cursor, end) })
                            .map_err(|_| crate::syscall::EFAULT)?
                    else {
                        break;
                    };
                    if address < cursor || address >= end || address & 4095 != 0 {
                        return Err(crate::syscall::EFAULT);
                    }
                    locations
                        .try_reserve(1)
                        .map_err(|_| crate::syscall::ENOMEM)?;
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
                .map_err(|_| crate::syscall::ENOMEM)?;
            *owner.value_mut() = Some(Work {
                pages,
                targets,
                extent,
                publication: Publication::Prepared,
                external,
            });
            let work = owner.value_mut().as_mut().ok_or(crate::syscall::EINVAL)?;
            for (root, address, affected) in locations {
                // SAFETY: same retained roots, reservation and VM exclusion.
                if let Some(page) = unsafe { paging::suspend_user_page(root, address) }
                    .map_err(|_| crate::syscall::EFAULT)?
                {
                    work.pages.push(Page {
                        record: page.into_record(),
                        zero: None,
                        affected,
                    });
                    // Publish the record into the cancellation owner BEFORE
                    // any later check can fail. Push cannot allocate here.
                    let page = work.pages.last_mut().ok_or(crate::syscall::EINVAL)?;
                    if let Some(boundary) = work.targets.preserved().iter().find(|boundary| {
                        affected && boundary.table == root && boundary.address == address
                    }) {
                        page.zero = Some(
                            page.record
                                .suffix_address(boundary.zero_from)
                                .map_err(|_| crate::syscall::EFAULT)?,
                        );
                    }
                }
            }
            if !work.pages.is_empty() {
                tlb_shootdown::invalidate_all().map_err(|_| crate::syscall::EIO)?;
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
        let owner = self.owner.as_mut().ok_or(crate::syscall::EINVAL)?;
        process::with_mapping_table(|_| {
            let work = owner.value_mut().as_mut().ok_or(crate::syscall::EINVAL)?;
            if !work.external || work.publication != Publication::Prepared {
                return Err(crate::syscall::EINVAL);
            }
            if !work.pages.iter().all(|page| work.current(page)) {
                return Err(crate::syscall::EFAULT);
            }
            work.extent.preflight()?;
            work.publication = Publication::InFlight;
            Ok(())
        })
    }

    /// The resource owner confirms storage is unchanged, not merely that an
    /// I/O request returned an error. Keep that decision across cleanup retry.
    pub(crate) fn confirm_unchanged(&mut self) -> Result<(), u64> {
        let owner = self.owner.as_mut().ok_or(crate::syscall::EINVAL)?;
        process::with_mapping_table(|_| {
            let work = owner.value_mut().as_mut().ok_or(crate::syscall::EINVAL)?;
            if !matches!(
                work.publication,
                Publication::InFlight | Publication::Unchanged
            ) {
                return Err(crate::syscall::EINVAL);
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
        let owner = self.owner.as_mut().ok_or(crate::syscall::EINVAL)?;
        let work = owner.value_mut().as_ref().ok_or(crate::syscall::EINVAL)?;
        if !work.external
            || !matches!(
                work.publication,
                Publication::InFlight | Publication::Requested | Publication::Published
            )
        {
            return Err(crate::syscall::EINVAL);
        }
        self.finish(true)
    }

    fn finish(&mut self, request_publication: bool) -> Result<(), u64> {
        let owner = self.owner.as_mut().ok_or(crate::syscall::EINVAL)?;
        process::with_mapping_table(|_| {
            let work = owner.value_mut().as_mut().ok_or(crate::syscall::EINVAL)?;
            if work.publication == Publication::Unchanged {
                return Err(crate::syscall::EINVAL);
            }
            if work.publication == Publication::InFlight && !request_publication {
                return Err(crate::syscall::EINVAL);
            }
            if work.publication == Publication::Unavailable {
                return Err(crate::syscall::EIO);
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
                return Err(crate::syscall::EFAULT);
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
                self.extent.mark_unavailable();
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
            Publication::InFlight | Publication::Requested => return Err(crate::syscall::EAGAIN),
        };
        while let Some(page) = self.pages.pop() {
            if !self.current(&page) {
                self.pages.push(page);
                return Err(crate::syscall::EFAULT);
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
                return Err(crate::syscall::EFAULT);
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
