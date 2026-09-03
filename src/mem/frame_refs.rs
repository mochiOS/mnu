use crate::result::{Kernel, Memory, Result};
use alloc::vec::Vec;

const EMPTY: u32 = 0;
const DELETED: u32 = 1;
const INITIAL_CAPACITY: usize = 64;

#[derive(Clone, Copy)]
struct Slot {
    phys: u64,
    refs: u32,
}

impl Slot {
    const EMPTY: Self = Self { phys: 0, refs: 0 };
}

pub(super) struct FrameReferenceTable {
    slots: Vec<Slot>,
    live: usize,
    deleted: usize,
}

impl FrameReferenceTable {
    pub(super) const fn new() -> Self {
        Self {
            slots: Vec::new(),
            live: 0,
            deleted: 0,
        }
    }

    pub(super) fn retain(&mut self, phys: u64) -> Result<()> {
        self.ensure_insert_capacity()?;
        let mut first_deleted = None;
        let mut index = Self::hash(phys) & (self.slots.len() - 1);
        loop {
            let slot = &mut self.slots[index];
            match slot.refs {
                EMPTY => {
                    let target = first_deleted.unwrap_or(index);
                    self.slots[target] = Slot { phys, refs: 2 };
                    self.live += 1;
                    if first_deleted.is_some() {
                        self.deleted -= 1;
                    }
                    return Ok(());
                }
                DELETED => {
                    first_deleted.get_or_insert(index);
                }
                _ if slot.phys == phys => {
                    slot.refs = slot
                        .refs
                        .checked_add(1)
                        .ok_or(Kernel::Memory(Memory::OutOfMemory))?;
                    return Ok(());
                }
                _ => {}
            }
            index = (index + 1) & (self.slots.len() - 1);
        }
    }

    pub(super) fn release(&mut self, phys: u64) -> bool {
        if self.slots.is_empty() {
            return true;
        }
        let mut index = Self::hash(phys) & (self.slots.len() - 1);
        loop {
            let slot = &mut self.slots[index];
            match slot.refs {
                EMPTY => return true,
                DELETED => {}
                2 if slot.phys == phys => {
                    slot.refs = DELETED;
                    self.live -= 1;
                    self.deleted += 1;
                    return false;
                }
                _ if slot.phys == phys => {
                    slot.refs -= 1;
                    return false;
                }
                _ => {}
            }
            index = (index + 1) & (self.slots.len() - 1);
        }
    }

    fn ensure_insert_capacity(&mut self) -> Result<()> {
        if self.slots.is_empty() {
            return self.rehash(INITIAL_CAPACITY);
        }
        if self.live + self.deleted + 1 <= self.slots.len() * 3 / 4 {
            return Ok(());
        }
        let capacity = if self.live + 1 <= self.slots.len() / 2 {
            self.slots.len()
        } else {
            self.slots
                .len()
                .checked_mul(2)
                .ok_or(Kernel::Memory(Memory::OutOfMemory))?
        };
        self.rehash(capacity)
    }

    fn rehash(&mut self, capacity: usize) -> Result<()> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| Kernel::Memory(Memory::OutOfMemory))?;
        slots.resize(capacity, Slot::EMPTY);
        for old in self.slots.drain(..) {
            if old.refs < 2 {
                continue;
            }
            let mut index = Self::hash(old.phys) & (capacity - 1);
            while slots[index].refs != EMPTY {
                index = (index + 1) & (capacity - 1);
            }
            slots[index] = old;
        }
        self.slots = slots;
        self.deleted = 0;
        Ok(())
    }

    fn hash(phys: u64) -> usize {
        let mut value = phys >> 12;
        value ^= value >> 30;
        value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value ^= value >> 27;
        value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
        (value ^ (value >> 31)) as usize
    }
}
