//! User placement must preserve the mappings needed to enter the kernel.
use super::{Kernel, Memory, PageTable, PageTableFlags as Flags, Result};
use crate::mem::scan_budget::Budget;
use crate::mem::sparse_page_walk::{self, Entry};

/// Bootstrap copies the first GiB's supervisor identity aliases into each
/// root. They are placeholders, except for the required kernel ranges below.
/// Explicit supervisor mappings elsewhere always retain their address space.
fn bootstrap_identity(address: u64, physical: u64) -> bool {
    address < (1 << 30) && address == physical
}

/// Check the complete range before allocation or hierarchy/PTE mutation.
/// The caller retains the root and excludes VM writers through publication.
pub(crate) fn check_user_mapping_range(table: u64, start: u64, length: u64) -> Result<()> {
    if first_conflict(table, start, length, true, &mut Budget::new())?.is_some() {
        return Err(Kernel::Memory(Memory::PermissionDenied));
    }
    Ok(())
}

/// Return the end of an occupied span, including supervisor mappings and
/// non-present retained user leaves. Caller excludes VM writers throughout.
pub(crate) fn user_mapping_conflict(
    table: u64,
    start: u64,
    length: u64,
    budget: &mut Budget,
) -> Result<Option<u64>> {
    first_conflict(table, start, length, false, budget)
}

fn first_conflict(
    table: u64,
    start: u64,
    length: u64,
    allow_user: bool,
    budget: &mut Budget,
) -> Result<Option<u64>> {
    if length == 0 {
        return Ok(None);
    }
    let last = start
        .checked_add(length - 1)
        .filter(|&last| last <= super::USER_SPACE_END)
        .ok_or(Kernel::Memory(Memory::InvalidAddress))?;
    let start = start & !4095;
    let end = (last & !4095) + 4096;
    if let Some((_, limit)) = super::required_kernel_ranges()
        .into_iter()
        .find(|&(base, limit)| base < limit && start < limit && base < end)
    {
        return Ok(Some(limit));
    }
    let offset = super::physical_memory_offset().ok_or(Kernel::Memory(Memory::NotMapped))?;
    let _smap = crate::cpu::SmapSmepGuard::new();
    let mut prefix = 0;
    let mut user_path = true;
    let occupied = sparse_page_walk::next_span(table, start, end, |table, index, level| {
        if !budget.take(1) {
            return Err(Kernel::Memory(Memory::OutOfMemory));
        }
        let pointer = table
            .checked_add(offset)
            .ok_or(Kernel::Memory(Memory::InvalidAddress))?;
        // SAFETY: the caller retains this root under VM writer exclusion.
        let entries = unsafe { &*(pointer as *const PageTable) };
        let entry = &entries[index];
        let flags = entry.flags();
        prefix = if level == 4 { 0 } else { prefix } | ((index as u64) << (12 + 9 * (level - 1)));
        user_path = (level == 4 || user_path) && flags.contains(Flags::USER_ACCESSIBLE);
        if entry.is_unused() {
            return Ok(Entry::Absent);
        }
        if flags.contains(super::KERNEL_MAPPING) {
            return Ok(Entry::Leaf);
        }
        if level > 1 && !flags.contains(Flags::PRESENT) {
            return Err(Kernel::Memory(Memory::NotMapped));
        }
        if level > 1 && flags.contains(Flags::HUGE_PAGE) {
            // Bit 12 is PAT on a 2MiB leaf, not part of its physical base.
            let physical = entry.addr().as_u64() & !((1 << 21) - 1);
            return if !flags.contains(Flags::USER_ACCESSIBLE)
                && level == 2
                && bootstrap_identity(prefix, physical)
            {
                Ok(Entry::Absent)
            } else {
                Ok(Entry::Leaf)
            };
        }
        if level == 1 {
            return Ok(
                if (allow_user && user_path)
                    || (!flags.contains(Flags::USER_ACCESSIBLE)
                        && bootstrap_identity(prefix, entry.addr().as_u64()))
                {
                    Entry::Absent
                } else {
                    Entry::Leaf
                },
            );
        }
        Ok(Entry::Branch(entry.addr().as_u64()))
    })
    .map_err(|error| match error {
        sparse_page_walk::Error::Backend(error) => error,
        _ => Kernel::Memory(Memory::InvalidAddress),
    })?;
    Ok(occupied.map(|(_, end)| end))
}
