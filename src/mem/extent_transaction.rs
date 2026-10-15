//! Native, owned mapping/cache extent coordination. No VM lock is retained by
//! the owner. This is NOT a storage transaction: publication remains fallible
//! and must not be used as an unconditional post-storage-commit operation.
use super::{
    mapping_targets::Targets,
    paging, tlb_shootdown,
    vm_object::{PreparedExtent, VmObject},
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
}

struct Work {
    pages: Vec<Page>,
    // Field order keeps root lifetime and backing admission until all records
    // have been resolved. Incomplete Work is never dropped by this module.
    targets: Targets,
    extent: PreparedExtent,
    publication: Publication,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Publication {
    Prepared,
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
    /// file path, or provider identity. A future public entry must validate a
    /// resource-control capability before reaching this constructor.
    pub(crate) fn prepare(object: &VmObject, old_length: u64, length: u64) -> Result<Self, u64> {
        // Reserve cancellation storage BEFORE edits, including failed prepare.
        let ticket = Ticket::new(None).map_err(|_| crate::syscall::ENOMEM)?;
        let mut owner = ticket.defer_on_drop(&PENDING);
        process::with_mapping_table(|table| {
            let extent = object.prepare_extent(old_length, length, |bytes| {
                Arc::try_new(bytes).map_err(|_| crate::syscall::ENOMEM)
            })?;
            let (start, end) = extent.revocation().unwrap_or((0, 0));
            let targets =
                Targets::capture(table, object.object_key(), start, end, extent.boundary())?;
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
                    locations.push((root, address));
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
            });
            let work = owner.value_mut().as_mut().ok_or(crate::syscall::EINVAL)?;
            for (root, address) in locations {
                // SAFETY: same retained roots, reservation and VM exclusion.
                if let Some(page) = unsafe { paging::suspend_user_page(root, address) }
                    .map_err(|_| crate::syscall::EFAULT)?
                {
                    work.pages.push(Page {
                        record: page.into_record(),
                        zero: None,
                    });
                    // Publish the record into the cancellation owner BEFORE
                    // any later check can fail. Push cannot allocate here.
                    let page = work.pages.last_mut().ok_or(crate::syscall::EINVAL)?;
                    if let Some(boundary) = work
                        .targets
                        .preserved()
                        .iter()
                        .find(|boundary| boundary.table == root && boundary.address == address)
                    {
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
    /// already be resolved by the caller; unconfirmed in-flight owner death
    /// still requires a separate protocol before exposing a public API.
    pub(crate) fn request_publication(&mut self) -> Result<(), u64> {
        self.finish(true)
    }

    fn finish(&mut self, request_publication: bool) -> Result<(), u64> {
        let owner = self.owner.as_mut().ok_or(crate::syscall::EINVAL)?;
        process::with_mapping_table(|_| {
            let work = owner.value_mut().as_mut().ok_or(crate::syscall::EINVAL)?;
            if request_publication && work.publication == Publication::Prepared {
                work.publication = Publication::Requested;
            }
            work.publish_cache()?;
            work.resolve()
        })?;
        // Every PTE is finished. Disarm enqueue and release pins/admission
        // outside the VM lock; root/provider destruction can run other cleanup.
        if let Some(owner) = self.owner.take() {
            drop(owner.into_ticket());
        }
        Ok(())
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
            Publication::Prepared => self.resolve(),
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
            Publication::Prepared => false,
            Publication::Published => true,
            // An irrevocable request cannot fall through to cancellation.
            Publication::Requested => return Err(crate::syscall::EAGAIN),
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
            let Page { record, zero } = page;
            // SAFETY: selected root is pinned, VM exclusion is held, and
            // published release is reachable only after all-CPU TLB ack.
            let result = unsafe {
                if !published || zero.is_some() {
                    record.try_restore()
                } else {
                    record.try_release()
                }
            };
            if let Err(record) = result {
                self.pages.push(Page { record, zero });
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
