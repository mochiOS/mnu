//! Owned extent targets selected under VM exclusion. Root pins retain physical
//! lifetime, not mapping exclusion: PTE access still requires the VM lock and
//! the caller's backing admission reservation throughout any unlocked period.
use super::{
    mapping_preservation_native::PreservedPage, mapping_revocation::virtual_overlap,
    root_lifetime::Pin, vm_object::ObjectKey,
};
use alloc::vec::Vec;
use mnu_abi::status::Error;

pub(crate) struct Targets {
    identity: ObjectKey,
    roots: Vec<(u64, Pin)>,
    ranges: Vec<(u64, u64, u64)>,
    preserved: Vec<PreservedPage>,
}

impl Targets {
    /// The caller retains the process/mapping lock during capture. No page
    /// tables or backing bytes change on validation/allocation failure.
    pub(crate) fn capture(
        table: &crate::task::process::ProcessTable,
        identity: ObjectKey,
        start: u64,
        end: u64,
        boundary: u64,
    ) -> Result<Self, Error> {
        Self::capture_filtered(table, identity, start, end, boundary, false)
    }

    /// Cache refresh targets shared aliases only. Private/COW frames retain
    /// their independent bytes, including in not-yet-published roots.
    pub(crate) fn capture_shared(
        table: &crate::task::process::ProcessTable,
        identity: ObjectKey,
        start: u64,
        end: u64,
    ) -> Result<Self, Error> {
        Self::capture_filtered(table, identity, start, end, 0, true)
    }

    fn capture_filtered(
        table: &crate::task::process::ProcessTable,
        identity: ObjectKey,
        start: u64,
        end: u64,
        boundary: u64,
        shared_only: bool,
    ) -> Result<Self, Error> {
        if start > end || start & 4095 != 0 || end & 4095 != 0 {
            return Err(Error::InvalidArgument);
        }
        let mut targets = Self {
            identity,
            roots: Vec::new(),
            ranges: Vec::new(),
            preserved: Vec::new(),
        };
        if start == end {
            return Ok(targets);
        }
        let detached = super::detached_roots::snapshot().map_err(|_| Error::ResourceUnavailable)?;
        for root in &detached {
            for mapping in root
                .mappings()
                .iter()
                .filter(|mapping| mapping.identity == identity && (!shared_only || mapping.shared))
            {
                targets.add(
                    root.table(),
                    mapping.start,
                    mapping.length,
                    mapping.offset,
                    start,
                    end,
                    boundary,
                )?;
            }
        }
        for process in table.iter() {
            let Some(root) = process.page_table() else {
                continue;
            };
            for region in process.memory_regions() {
                if shared_only && !region.is_shared() {
                    continue;
                }
                if region
                    .backing()
                    .file_object()
                    .map(|object| object.object_key())
                    != Some(identity)
                {
                    continue;
                }
                targets.add(
                    root,
                    region.start(),
                    region.len(),
                    region.backing().file_offset(),
                    start,
                    end,
                    boundary,
                )?;
            }
        }
        // Ambiguous/duplicate virtual ownership must fail before suspension.
        targets.ranges.sort_unstable();
        if targets
            .ranges
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0 && pair[1].1 < pair[0].2)
        {
            return Err(Error::InvalidArgument);
        }
        Ok(targets)
    }

    fn add(
        &mut self,
        table: u64,
        address: u64,
        length: u64,
        offset: u64,
        start: u64,
        end: u64,
        boundary: u64,
    ) -> Result<(), Error> {
        if table == 0
            || (table | address | length | offset) & 4095 != 0
            || !address
                .checked_add(length)
                .is_some_and(|end| end <= 0x0000_8000_0000_0000)
        {
            return Err(Error::InvalidArgument);
        }
        let Some((low, high)) = virtual_overlap(address, length, offset, start, end)
            .map_err(|_| Error::InvalidArgument)?
        else {
            return Ok(());
        };
        let preserved = PreservedPage::for_mapping(table, address, length, offset, boundary)?
            .filter(|page| page.address >= low && page.address < high);
        self.ranges
            .try_reserve(1)
            .map_err(|_| Error::ResourceUnavailable)?;
        if preserved.is_some() {
            self.preserved
                .try_reserve(1)
                .map_err(|_| Error::ResourceUnavailable)?;
        }
        if !self.roots.iter().any(|(root, _)| *root == table) {
            self.roots
                .try_reserve(1)
                .map_err(|_| Error::ResourceUnavailable)?;
            let pin =
                super::root_lifetime_native::pin(table).map_err(|_| Error::ResourceUnavailable)?;
            self.roots.push((table, pin));
        }
        self.ranges.push((table, low, high));
        if let Some(page) = preserved {
            self.preserved.push(page);
        }
        Ok(())
    }

    pub(crate) fn identity(&self) -> ObjectKey {
        self.identity
    }

    pub(crate) fn ranges(&self) -> impl Iterator<Item = (u64, u64, u64)> + '_ {
        self.ranges.iter().copied()
    }

    pub(crate) fn preserved(&self) -> &[PreservedPage] {
        &self.preserved
    }

    /// Permission for this particular captured span, not every address in a
    /// pinned root. This does not by itself authorize page-table access.
    pub(crate) fn contains(&self, table: u64, start: u64, end: u64) -> bool {
        start < end
            && self
                .ranges
                .iter()
                .any(|&(root, low, high)| root == table && low <= start && end <= high)
    }
}
