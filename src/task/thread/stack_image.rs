//! A prepared stack alias must not detach the running image's alias or change
//! stack ownership while a later image-preparation operation can still fail.
use super::{
    KSTACK_PAGE_BYTES, KSTACK_SLOT_RESERVED, KSTACK_SLOTS, KernelStackSlot, VirtAddr,
    map_stack_page_in_user_table, stack_slot_index, unmap_stack_from_table,
};

pub struct PreparedKernelStack {
    slot: usize,
    base: u64,
    target: u64,
    previous: KernelStackSlot,
    mapped: usize,
    committed: bool,
}

pub fn prepare_kernel_stack_user_table(base: u64, target: u64) -> Option<PreparedKernelStack> {
    if target == 0 || target & 4095 != 0 {
        return None;
    }
    let index = stack_slot_index(base)?;
    let previous = {
        let mut slots = KSTACK_SLOTS.lock();
        let slot = &mut slots[index];
        if slot.mapped_pages == 0
            || slot.mapped_pages == KSTACK_SLOT_RESERVED
            || slot.user_page_table == target
        {
            return None;
        }
        let previous = *slot;
        slot.mapped_pages = KSTACK_SLOT_RESERVED;
        previous
    };
    let mut prepared = PreparedKernelStack {
        slot: index,
        base,
        target,
        previous,
        mapped: 0,
        committed: false,
    };
    while prepared.mapped < usize::from(previous.mapped_pages) {
        let address = base + (prepared.mapped * KSTACK_PAGE_BYTES) as u64;
        let physical = crate::mem::paging::translate_addr(VirtAddr::new(address))?;
        if !map_stack_page_in_user_table(target, address, physical.as_u64()) {
            return None;
        }
        prepared.mapped += 1;
    }
    Some(prepared)
}

impl PreparedKernelStack {
    /// No fallible operation remains after this ownership transition. The
    /// caller has finished admission/revocation and stopped image siblings.
    pub fn commit(mut self) {
        if self.previous.user_page_table != 0
            && !unmap_stack_from_table(self.previous.user_page_table, self.base, self.mapped)
        {
            crate::audit::log(
                crate::audit::AuditEventKind::Quarantine,
                "old kernel stack mapping could not be fully detached during exec",
            );
        }
        KSTACK_SLOTS.lock()[self.slot] = KernelStackSlot {
            user_page_table: self.target,
            ..self.previous
        };
        self.committed = true;
    }
}

impl Drop for PreparedKernelStack {
    fn drop(&mut self) {
        if !self.committed {
            let _ = unmap_stack_from_table(self.target, self.base, self.mapped);
            KSTACK_SLOTS.lock()[self.slot] = self.previous;
        }
    }
}
