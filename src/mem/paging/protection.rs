//! Permission-only journals: allocate and validate before touching any PTE.
//! COW storage is materialized by its eventual write fault, never by mprotect.
use super::{PageTableEntry, PageTableFlags as Flags, Result, TableEdit};
use core::{marker::PhantomData, ptr::NonNull};

#[must_use]
pub(crate) struct PreparedProtection<'owner> {
    entry: NonNull<PageTableEntry>,
    table: u64,
    address: u64,
    before: Flags,
    after: Flags,
    applied: bool,
    _owner: PhantomData<&'owner mut ()>,
}

impl<'owner> TableEdit<'owner> {
    pub(crate) fn prepare_protection(
        &mut self,
        address: u64,
        present: bool,
        writable: bool,
        executable: bool,
    ) -> Result<Option<PreparedProtection<'owner>>> {
        if present && writable && executable {
            return Err(super::Kernel::Memory(super::Memory::PermissionDenied));
        }
        let _smap = crate::cpu::SmapSmepGuard::new();
        Ok(
            super::with_user_leaf_entry_mut(self.table(), address, |entry| {
                let before = entry.flags();
                if entry.is_unused() || !before.contains(Flags::USER_ACCESSIBLE) {
                    return None;
                }
                let mut after = before;
                after.remove(Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE);
                if present {
                    after.insert(Flags::PRESENT);
                    // Write permission authorizes a future COW fault. Publishing
                    // RW on the shared frame would bypass private-copy isolation.
                    if writable && !before.contains(super::COPY_ON_WRITE) {
                        after.insert(Flags::WRITABLE);
                    }
                }
                if !present || !executable {
                    after.insert(Flags::NO_EXECUTE);
                }
                after = Flags::from_bits_retain(super::super::cow_access::with_write_access(
                    after.bits(),
                    writable,
                ));
                Some(PreparedProtection {
                    entry: NonNull::from(entry),
                    table: self.table(),
                    address,
                    before,
                    after,
                    applied: false,
                    _owner: PhantomData,
                })
            })
            .flatten(),
        )
    }
}
impl PreparedProtection<'_> {
    fn write(&mut self, flags: Flags) {
        let _smap = crate::cpu::SmapSmepGuard::new();
        // SAFETY: TableEdit tied this journal to root retention and VM writer
        // exclusion. No leaf pointer outlives that scope; no frame is replaced.
        let entry = unsafe { self.entry.as_mut() };
        let old = entry.flags();
        let hardware = old & (Flags::ACCESSED | Flags::DIRTY);
        entry.set_addr(entry.addr(), flags | hardware);
        super::record_user_leaf_change(self.table, old, entry.flags());
        super::flush_page_if_active(self.table, self.address);
    }
    pub(crate) fn apply(&mut self) {
        self.write(self.after);
        self.applied = true;
    }
    pub(crate) fn restore(&mut self) {
        if self.applied {
            self.write(self.before);
            self.applied = false;
        }
    }
    pub(crate) fn commit(mut self) {
        self.applied = false;
    }
}
impl Drop for PreparedProtection<'_> {
    fn drop(&mut self) {
        self.restore();
    }
}
