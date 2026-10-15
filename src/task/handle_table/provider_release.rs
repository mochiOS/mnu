//! A provider reserves its release node before publication. Final-reference
//! destruction, batch extraction and retry only move existing allocations.
use super::ProviderRelease;
use alloc::boxed::Box;

struct Node {
    release: ProviderRelease,
    next: Option<Box<Node>>,
}

pub(crate) struct Ticket(Box<Node>);

impl Ticket {
    pub(super) fn new(release: ProviderRelease) -> Result<Self, u64> {
        Box::try_new(Node {
            release,
            next: None,
        })
        .map(Self)
        .map_err(|_| mnu_abi::ENOMEM)
    }

    pub(crate) fn release(&self) -> ProviderRelease {
        self.0.release
    }
}

#[derive(Default)]
pub(crate) struct Pending {
    head: Option<Box<Node>>,
}

impl Pending {
    pub(super) const fn new() -> Self {
        Self { head: None }
    }

    pub(super) fn push(&mut self, mut ticket: Ticket) {
        ticket.0.next = self.head.take();
        self.head = Some(ticket.0);
    }

    pub(crate) fn pop(&mut self) -> Option<Ticket> {
        let mut node = self.head.take()?;
        self.head = node.next.take();
        Some(Ticket(node))
    }

    /// A detached batch runs oldest-first, as the former vector queue did.
    /// New arrivals and retries remain in the shared queue for the next pass.
    pub(super) fn reversed(mut self) -> Self {
        let mut reversed = Self::new();
        while let Some(ticket) = self.pop() {
            reversed.push(ticket);
        }
        reversed
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        // Avoid recursive Box-chain destruction for large detached batches.
        while self.pop().is_some() {}
    }
}
