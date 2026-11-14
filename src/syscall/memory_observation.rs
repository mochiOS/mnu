//! Own-address-space RAM observation and private anonymous discard.
use super::{current_pid, memory_range_is_mapped};
use mnu_abi::{status::Error, SUCCESS};

/// Bounded observation of the caller's RAM leaves. Never faults source pages
/// in, consults another process, or exports a physical address. Output copying
/// runs after releasing PROC, and may itself fault in an output page.
///
/// The source address is page-aligned and length is nonzero. Capacity must
/// equal the rounded page count, at most 256. Each output byte describes one
/// page at the observation point; it is not a pin or a promise of future
/// residency. Retained RAM behind an inaccessible leaf still counts as RAM.
pub fn residency(address: u64, length: u64, output: u64, capacity: u64) -> u64 {
    if address & 4095 != 0 || length == 0 {
        return Error::InvalidArgument.into_raw();
    }
    if !crate::syscall::is_canonical_user_range(address, length) {
        return Error::InvalidAddress.into_raw();
    }
    let count = (length - 1) / 4096 + 1;
    if count > 256 || capacity != count {
        return Error::InvalidArgument.into_raw();
    }
    let end = address + count * 4096;
    let Some(pid) = current_pid() else {
        return Error::NotReady.into_raw();
    };
    let mut snapshot = [0u8; 256];
    let observed = crate::task::with_process(pid, |process| {
        let table = process.page_table().ok_or(Error::NotReady)?;
        if !memory_range_is_mapped(process, table, address, end) {
            return Err(Error::InvalidAddress);
        }
        for (index, byte) in snapshot[..count as usize].iter_mut().enumerate() {
            let page = address + index as u64 * 4096;
            let leaf = crate::mem::paging::user_page_is_resident(table, page);
            let backing = if leaf {
                false
            } else {
                process
                    .find_memory_region(page)
                    .map(|region| region.backing_page_is_resident(page))
                    .transpose()?
                    .unwrap_or(false)
            };
            *byte = u8::from(leaf || backing);
        }
        Ok(())
    });
    match observed {
        Some(Ok(())) => {
            match crate::syscall::copy_to_user_native(output, &snapshot[..count as usize]) {
                Ok(()) => count,
                Err(error) => error.into_raw(),
            }
        }
        Some(Err(error)) => error.into_raw(),
        None => Error::NotReady.into_raw(),
    }
}

/// Release RAM references using the existing transactional PTE revocation and
/// TLB acknowledgement mechanism. Keep the original reservation/access policy;
/// shared/file/device mappings never enter this operation.
///
/// Both endpoints are page-aligned. Validation covers the complete range
/// before any revocation, so a hole or an unsupported backing cannot discard a
/// validated prefix. Captured anonymous bytes are reset only after successful
/// revocation; changing the access policy is a separate operation.
pub fn discard(address: u64, length: u64) -> u64 {
    use crate::mem::{mapping_revocation as transaction, mapping_revocation_native::Native};
    use crate::task::process::MemoryBacking;
    if address & 4095 != 0 || length & 4095 != 0 {
        return Error::InvalidArgument.into_raw();
    }
    if length == 0 {
        return SUCCESS;
    }
    if !crate::syscall::is_canonical_user_range(address, length) {
        return Error::InvalidAddress.into_raw();
    }
    let end = address + length;
    let Some(pid) = current_pid() else {
        return Error::NotReady.into_raw();
    };
    let result = crate::task::with_process_mut(pid, |process| {
        let table = process.page_table().ok_or(Error::NotReady)?;
        // Every page must be covered by an ordinary private anonymous region,
        // not merely an untracked ELF leaf, DMA allocation or MMIO mapping.
        let mut cursor = address;
        while cursor < end {
            let region = process
                .find_memory_region(cursor)
                .ok_or(Error::InvalidAddress)?;
            if region.is_shared() || !matches!(region.backing(), MemoryBacking::Anonymous { .. }) {
                return Err(Error::Unsupported);
            }
            cursor = region.end().ok_or(Error::InvalidAddress)?.min(end);
        }
        crate::mem::mapping_admission::check_native(process.memory_regions(), address, end)?;
        // SAFETY: PROC retains the root and excludes every PTE writer through
        // revocation, remote TLB acknowledgement and RAM reference release.
        let mut backend = unsafe { Native::for_process(process, true) };
        transaction::revoke([(table, address, end)], &mut backend).map_err(
            |error| match error {
                transaction::Error::InvalidRange => Error::InvalidArgument,
                transaction::Error::Allocation => Error::ResourceUnavailable,
                transaction::Error::Backend(error) => error,
            },
        )?;
        // Captured anonymous backing must not resurrect pre-discard contents
        // on the next fault. This cannot allocate or fail after revocation.
        for region in process.memory_regions_mut() {
            let start = address.max(region.start());
            let limit = end.min(region.end().unwrap_or(0));
            if start >= limit {
                continue;
            }
            let offset = (start - region.start()) as usize;
            let count = (limit - start) as usize;
            if let MemoryBacking::Anonymous { data, .. } = region.backing_mut() {
                let first = offset.min(data.len());
                let last = offset.saturating_add(count).min(data.len());
                data[first..last].fill(0);
            }
        }
        Ok(())
    });
    match result {
        Some(Ok(())) => SUCCESS,
        Some(Err(error)) => error.into_raw(),
        None => Error::NotReady.into_raw(),
    }
}
