//! Native adapter used only inside the process-table/mapping lock scope.
use super::{mapping_revocation::Backend, paging, tlb_shootdown};

pub(crate) struct Native<'a> {
    // Retain the borrow for the entire suspension/synchronization transaction.
    table: &'a crate::task::process::ProcessTable,
}

impl<'a> Native<'a> {
    /// # Safety
    /// Hold the mapping lock, keep all referenced tables alive, and exclude
    /// every PTE writer until the complete transaction has restored/released.
    pub(crate) unsafe fn new(table: &'a crate::task::process::ProcessTable) -> Self {
        Self { table }
    }
}

impl Backend for Native<'_> {
    type Page = paging::SuspendedUserPage;
    type Error = u64;

    fn suspend(&mut self, table: u64, address: u64) -> Result<Option<Self::Page>, u64> {
        // Never walk an arbitrary physical address supplied in a plan. It must
        // belong to an address space retained in this locked process table.
        if !self
            .table
            .iter()
            .any(|process| process.page_table() == Some(table))
        {
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
            page.release();
        }
    }
}
