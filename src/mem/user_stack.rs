//! Shared observation/admission rules for the native initial stack.

/// Preserve the existing native downward-growth limit. No POSIX policy is
/// interpreted here; callers still supply and own ordinary worker stacks.
pub(crate) const MAX_INITIAL_STACK_BYTES: u64 = 8 * 1024 * 1024;

/// Whether an extension would collide with reserved/device/mapped memory.
/// The caller must hold the same process VM lock used by map/unmap/faults.
pub(crate) fn collides(process: &crate::task::Process, base: u64, length: u64) -> bool {
    if length == 0 {
        return false;
    }
    let Some(end) = base.checked_add(length) else {
        return true;
    };
    let Some(table) = process.page_table() else {
        return true;
    };
    process.memory_regions().iter().any(|region| {
        region
            .end()
            .is_none_or(|limit| base < limit && region.start() < end)
    }) || process.find_mmio_mapping_by_addr(base, length).is_some()
        || process.find_dma_buffer_by_addr(base, length).is_some()
        || crate::mem::paging::is_user_range_occupied_in_table(table, base, length)
}

/// Find the largest presently admissible contiguous stack extent. A binary
/// search clips growth at the highest collision; no page is mapped or read.
/// `reserved_top` follows the initial-image loader convention: one guard page
/// above the exclusive usable top. The caller stabilizes the address space.
pub(crate) fn bounds(
    committed: u64,
    reserved_top: u64,
    page_size: u64,
    mut collides: impl FnMut(u64, u64) -> bool,
) -> Option<mnu_abi::ProcessInitialStackInfo> {
    if !page_size.is_power_of_two()
        || committed == 0
        || committed & (page_size - 1) != 0
        || reserved_top & (page_size - 1) != 0
    {
        return None;
    }
    let upper = reserved_top.checked_sub(page_size)?;
    if committed >= upper {
        return None;
    }
    let floor = reserved_top.saturating_sub(MAX_INITIAL_STACK_BYTES);
    let floor = floor.checked_add(page_size - 1)? & !(page_size - 1);
    // Already committed space remains valid even if it exceeds the grow limit.
    let mut low = floor.min(committed);
    let mut high = committed;
    while low < high {
        let middle = low + ((high - low) / page_size / 2) * page_size;
        if collides(middle, committed - middle) {
            low = middle.checked_add(page_size)?;
        } else {
            high = middle;
        }
    }
    Some(mnu_abi::ProcessInitialStackInfo {
        lower_bound: low,
        committed_lower_bound: committed,
        upper_bound: upper,
    })
}
