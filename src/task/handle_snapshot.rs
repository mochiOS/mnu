//! Immutable caller-table references for later explicit, attenuated delegation.
//! This is separate from VM images and contains no FD or launch policy.
use super::handle_table::{HandleRights, ObjectHandle, ObjectHandleEntry};
use alloc::vec::Vec;

struct CapturedHandle {
    handle: ObjectHandle,
    rights: HandleRights,
    // Non-transferable objects contribute metadata only. In particular, a
    // private capture container must never retain nested capture containers.
    exportable: Option<ObjectHandleEntry>,
}

pub struct HandleSnapshot {
    entries: Vec<CapturedHandle>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExportError {
    Missing,
    Denied,
}

impl HandleSnapshot {
    /// Input is the caller's ordered table under its normal table lock.
    pub(super) fn capture(
        entries: impl ExactSizeIterator<Item = (ObjectHandle, ObjectHandleEntry)>,
    ) -> Result<Self, ()> {
        let mut captured = Vec::new();
        captured.try_reserve_exact(entries.len()).map_err(|_| ())?;
        for (handle, entry) in entries {
            let rights = entry.rights();
            let exportable = if rights.contains(HandleRights::TRANSFER) {
                Some(entry)
            } else {
                None
            };
            captured.push(CapturedHandle {
                handle,
                rights,
                exportable,
            });
        }
        Ok(Self { entries: captured })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn describe(&self) -> impl ExactSizeIterator<Item = mnu_abi::HandleInfo> + '_ {
        self.entries.iter().map(|entry| mnu_abi::HandleInfo {
            handle: entry.handle.raw(),
            reserved: 0,
            rights: entry.rights.bits(),
        })
    }

    /// Resolves the captured reference, never a possibly reused live slot.
    /// TRANSFER is required even for empty requested rights; DUPLICATE does
    /// not substitute for delegation authority. Requested rights may only
    /// shrink the captured rights, exactly as for a live-table export.
    pub fn export_restricted(
        &self,
        source: ObjectHandle,
        requested: HandleRights,
    ) -> Result<ObjectHandleEntry, ExportError> {
        let index = self
            .entries
            .binary_search_by_key(&source, |entry| entry.handle)
            .map_err(|_| ExportError::Missing)?;
        self.entries[index]
            .exportable
            .as_ref()
            .and_then(|entry| entry.restricted(requested))
            .ok_or(ExportError::Denied)
    }
}
