//! Immediate PTE tokens remain bound to their original VM-lock scope. A
//! recorded token contains coordinates, not a borrowed page-table pointer;
//! every later edit rewalks and checks the still-suspended entry under VM lock.
use super::{
    Kernel, Memory, PageTableEntry, PageTableFlags, Result, physical_memory_offset,
    release_user_frame, with_user_leaf_entry_mut,
};

/// A temporarily non-present user PTE. Its mapping reference remains owned
/// until restore/release. Never expose either token type through a syscall.
pub(crate) struct SuspendedUserPage {
    entry: *mut PageTableEntry,
    record: RecordedUserPage,
}

/// No raw PTE pointer or reference survives in this representation. The
/// enclosing owner must retain root pins AND backing/mapping exclusion; the
/// record itself grants neither. Dropping it does not finish the mapping.
#[must_use = "retain in a journal until explicit restoration or release"]
pub(crate) struct RecordedUserPage {
    table: u64,
    address: u64,
    original: PageTableEntry,
}

/// # Safety
/// Hold the process/mapping lock and keep this table alive through immediate
/// restore/release. No other writer may edit the captured leaf. Before taking
/// a record outside that lock, retain root lifetime and exclude edits to the
/// selected mapping independently (a root pin alone is not enough).
pub(crate) unsafe fn suspend_user_page(
    table_phys: u64,
    page_addr: u64,
) -> Result<Option<SuspendedUserPage>> {
    if table_phys == 0
        || table_phys & 4095 != 0
        || page_addr & 4095 != 0
        || page_addr >= 0x0000_8000_0000_0000
    {
        return Err(Kernel::Memory(Memory::InvalidAddress));
    }
    if physical_memory_offset().is_none() {
        return Err(Kernel::Memory(Memory::NotMapped));
    }
    let _smap_guard = crate::cpu::SmapSmepGuard::new();
    Ok(with_user_leaf_entry_mut(table_phys, page_addr, |entry| {
        if entry.is_unused() || !entry.flags().contains(PageTableFlags::USER_ACCESSIBLE) {
            return None;
        }
        let original = entry.clone();
        let mut flags = entry.flags();
        flags.remove(PageTableFlags::PRESENT);
        entry.set_addr(entry.addr(), flags);
        Some(SuspendedUserPage {
            entry,
            record: RecordedUserPage {
                table: table_phys,
                address: page_addr,
                original,
            },
        })
    })
    .flatten())
}

impl SuspendedUserPage {
    pub(crate) fn suffix_address(&self, offset: usize) -> Result<(u64, usize)> {
        self.record.suffix_address(offset)
    }

    /// Discard the borrowed pointer, retaining only an explicit mapping record.
    /// The owner is still responsible for lifetime, exclusion and finalization.
    pub(crate) fn into_record(self) -> RecordedUserPage {
        self.record
    }

    /// # Safety
    /// The original mapping lock is still held and the table is alive.
    pub(crate) unsafe fn restore(self) {
        let _smap_guard = crate::cpu::SmapSmepGuard::new();
        unsafe {
            *self.entry = self.record.original;
        }
    }

    /// # Safety
    /// As for restore, with all-CPU TLB acknowledgement after suspension.
    pub(crate) unsafe fn release(self) {
        let frame = self.record.original.addr().as_u64();
        unsafe {
            self.detach();
        }
        release_user_frame(frame);
    }

    /// # Safety
    /// Same exclusion and synchronization as release; storage remains owned
    /// externally, for example a device MMIO aperture.
    pub(crate) unsafe fn detach(self) {
        let _smap_guard = crate::cpu::SmapSmepGuard::new();
        unsafe {
            (*self.entry).set_unused();
        }
    }
}

impl RecordedUserPage {
    pub(crate) fn location(&self) -> (u64, u64) {
        (self.table, self.address)
    }

    /// Validate physical access without touching storage. The record's owner
    /// must keep the mapped frame alive until a later validated operation.
    pub(crate) fn suffix_address(&self, offset: usize) -> Result<(u64, usize)> {
        if offset > 4096 {
            return Err(Kernel::Memory(Memory::InvalidAddress));
        }
        let length = 4096 - offset;
        let start = physical_memory_offset()
            .and_then(|base| base.checked_add(self.original.addr().as_u64()))
            .and_then(|base| base.checked_add(offset as u64))
            .filter(|start| start.checked_add(length as u64).is_some())
            .ok_or(Kernel::Memory(Memory::NotMapped))?;
        Ok((start, length))
    }

    fn matches(&self, current: &PageTableEntry) -> bool {
        // Old hardware translations can set A/D before the TLB barrier. These
        // bits do not change ownership; every other flag and the frame must
        // still match, and PRESENT must remain clear.
        let accessed_dirty = (PageTableFlags::ACCESSED | PageTableFlags::DIRTY).bits();
        current.addr() == self.original.addr()
            && current.flags().bits() & !accessed_dirty
                == self.original.flags().bits() & !(accessed_dirty | PageTableFlags::PRESENT.bits())
    }

    /// # Safety
    /// Hold the VM lock and retain the root. This only checks the entry;
    /// admission exclusion must remain held until the eventual edit too.
    pub(crate) unsafe fn is_current(&self) -> bool {
        let _smap_guard = crate::cpu::SmapSmepGuard::new();
        with_user_leaf_entry_mut(self.table, self.address, |entry| self.matches(entry))
            .unwrap_or(false)
    }

    unsafe fn try_edit(
        self,
        edit: impl FnOnce(&mut PageTableEntry, &PageTableEntry),
    ) -> core::result::Result<(), Self> {
        let _smap_guard = crate::cpu::SmapSmepGuard::new();
        let changed = with_user_leaf_entry_mut(self.table, self.address, |entry| {
            if !self.matches(entry) {
                return false;
            }
            edit(entry, &self.original);
            true
        })
        .unwrap_or(false);
        if changed { Ok(()) } else { Err(self) }
    }

    /// # Safety
    /// Hold the VM lock, root lifetime and selected-mapping exclusion. A
    /// missing/replaced entry leaves both the current PTE and token untouched.
    pub(crate) unsafe fn try_restore(self) -> core::result::Result<(), Self> {
        unsafe {
            self.try_edit(|entry, original| {
                let hardware = entry.flags() & (PageTableFlags::ACCESSED | PageTableFlags::DIRTY);
                entry.set_addr(original.addr(), original.flags() | hardware);
            })
        }
    }

    /// # Safety
    /// As for try_restore, with successful all-CPU TLB acknowledgement after
    /// suspension. A rejected edit must not release any frame reference.
    pub(crate) unsafe fn try_release(self) -> core::result::Result<(), Self> {
        let frame = self.original.addr().as_u64();
        unsafe {
            self.try_detach()?;
        }
        release_user_frame(frame);
        Ok(())
    }

    /// # Safety
    /// Same exclusion/lifetime/synchronization as try_release, but external
    /// storage keeps ownership, so no allocator-owned frame is released.
    pub(crate) unsafe fn try_detach(self) -> core::result::Result<(), Self> {
        unsafe { self.try_edit(|entry, _| entry.set_unused()) }
    }
}
