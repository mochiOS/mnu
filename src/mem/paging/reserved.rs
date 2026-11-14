//! User placement must preserve the mappings needed to enter the kernel.
use super::{Kernel, Memory, PageTable, PageTableFlags as Flags, Result};
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
    if length == 0 {
        return Ok(());
    }
    let last = start
        .checked_add(length - 1)
        .filter(|&last| last <= super::USER_SPACE_END)
        .ok_or(Kernel::Memory(Memory::InvalidAddress))?;
    let start = start & !4095;
    let end = (last & !4095) + 4096;
    if super::required_kernel_ranges()
        .into_iter()
        .any(|(base, limit)| base < limit && start < limit && base < end)
    {
        return Err(Kernel::Memory(Memory::PermissionDenied));
    }
    let offset = super::physical_memory_offset().ok_or(Kernel::Memory(Memory::NotMapped))?;
    let _smap = crate::cpu::SmapSmepGuard::new();
    let mut prefix = 0;
    let mut user_path = true;
    let occupied = sparse_page_walk::next(table, start, end, |table, index, level| {
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
        if level > 1 && !flags.contains(Flags::PRESENT) {
            return Err(Kernel::Memory(Memory::NotMapped));
        }
        if level > 1 && flags.contains(Flags::HUGE_PAGE) {
            if flags.contains(Flags::USER_ACCESSIBLE) || level != 2 {
                return Err(Kernel::Memory(Memory::AlreadyMapped));
            }
            // Bit 12 is PAT on a 2MiB leaf, not part of its physical base.
            let physical = entry.addr().as_u64() & !((1 << 21) - 1);
            return if bootstrap_identity(prefix, physical) {
                Ok(Entry::Absent)
            } else {
                Err(Kernel::Memory(Memory::PermissionDenied))
            };
        }
        if level == 1 {
            return Ok(
                if user_path || bootstrap_identity(prefix, entry.addr().as_u64()) {
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
    if occupied.is_some() {
        return Err(Kernel::Memory(Memory::PermissionDenied));
    }
    Ok(())
}
