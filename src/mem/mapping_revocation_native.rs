//! Native adapter used only inside the process-table/mapping lock scope.
use super::{mapping_revocation::Backend, paging, tlb_shootdown};

pub(crate) struct Native<'a> {
    // Retain the borrow for the entire suspension/synchronization transaction.
    roots: Roots<'a>,
    release_frames: bool,
}

enum Roots<'a> {
    All(
        &'a crate::task::process::ProcessTable,
        &'a [alloc::sync::Arc<super::detached_roots::Root>],
    ),
    One(&'a crate::task::process::Process),
}

impl<'a> Native<'a> {
    pub(crate) fn owns_ram_frames(&self) -> bool {
        self.release_frames
    }

    fn owns(&self, table: u64) -> bool {
        match self.roots {
            Roots::All(table_guard, roots) => {
                table_guard
                    .iter()
                    .any(|process| process.page_table() == Some(table))
                    || roots
                        .iter()
                        .any(|root| !root.published() && root.table() == table)
            }
            Roots::One(process) => process.page_table() == Some(table),
        }
    }
    /// # Safety
    /// Hold the mapping lock, keep all referenced tables alive, and exclude
    /// every PTE writer until the complete transaction has restored/released.
    pub(crate) unsafe fn new(table: &'a crate::task::process::ProcessTable) -> Self {
        Self {
            roots: Roots::All(table, &[]),
            release_frames: true,
        }
    }

    /// # Safety
    /// Same lock/lifetime requirements as new. Pins retain unpublished roots
    /// until every suspended PTE has been restored or released.
    pub(crate) unsafe fn with_detached(
        table: &'a crate::task::process::ProcessTable,
        roots: &'a [alloc::sync::Arc<super::detached_roots::Root>],
    ) -> Self {
        Self {
            roots: Roots::All(table, roots),
            release_frames: true,
        }
    }

    /// # Safety
    /// As for new, but the retained mapping lock guards one process. Set
    /// release_frames only for mappings that own RAM frame references.
    pub(crate) unsafe fn for_process(
        process: &'a crate::task::process::Process,
        release_frames: bool,
    ) -> Self {
        Self {
            roots: Roots::One(process),
            release_frames,
        }
    }
}

impl Backend for Native<'_> {
    type Page = paging::SuspendedUserPage;
    type Error = u64;

    fn next_page(&mut self, table: u64, start: u64, end: u64) -> Result<Option<u64>, u64> {
        if !self.owns(table) {
            return Err(crate::syscall::EFAULT);
        }
        // SAFETY: the retained mapping lock excludes all writers and teardown.
        unsafe { paging::next_user_page_entry(table, start, end) }
            .map_err(|_| crate::syscall::EFAULT)
    }

    fn suspend(&mut self, table: u64, address: u64) -> Result<Option<Self::Page>, u64> {
        // Never walk an arbitrary physical address supplied in a plan. It must
        // belong to an address space retained in this locked process table.
        if !self.owns(table) {
            return Err(crate::syscall::EFAULT);
        }
        // SAFETY: Native::new's caller excludes writers/faults/teardown and
        // retains the locked process table throughout this transaction.
        unsafe { paging::suspend_user_page(table, address) }.map_err(|_| crate::syscall::EFAULT)
    }

    fn restore(&mut self, page: Self::Page) {
        // SAFETY: same retained table and mapping lock as suspension.
        unsafe {
            page.restore();
        }
    }

    fn synchronize(&mut self) -> Result<(), u64> {
        tlb_shootdown::invalidate_all().map_err(|_| crate::syscall::EIO)
    }

    fn release(&mut self, page: Self::Page) {
        // SAFETY: the transaction calls this only after successful all-CPU
        // synchronization; its process-table borrow still retains the PTE.
        unsafe {
            if self.release_frames {
                page.release();
            } else {
                page.detach();
            }
        }
    }
}
