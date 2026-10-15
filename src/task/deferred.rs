//! Preallocated ownership transfer to a caller-selected cleanup context.
//! Push/pop/reverse never allocate or run payload cleanup. Detach a batch
//! before acquiring the resource's locks or dropping any queued payload.
use alloc::boxed::Box;
use crate::interrupt::spinlock::SpinLock;

struct Node<T> {
    value: Option<T>,
    next: Option<Box<Node<T>>>,
}

pub(crate) struct Ticket<T>(Box<Node<T>>);

impl<T> Ticket<T> {
    /// Reserve before publishing resources which will need deferred cleanup.
    /// On failure ownership of the value is returned to the caller.
    pub(crate) fn new(value: T) -> Result<Self, T> {
        // Allocate an empty node first so allocation failure cannot destroy a
        // payload which already requires a particular cleanup context.
        let node = Box::try_new(Node {
            value: None,
            next: None,
        });
        match node {
            Ok(mut node) => {
                node.value = Some(value);
                Ok(Self(node))
            }
            Err(_) => Err(value),
        }
    }

    pub(crate) fn value(&self) -> &T {
        // Only construction and consuming extraction change this Option.
        self.0.value.as_ref().unwrap()
    }

    pub(crate) fn value_mut(&mut self) -> &mut T {
        self.0.value.as_mut().unwrap()
    }

    pub(crate) fn into_value(mut self) -> T {
        self.0.value.take().unwrap()
    }

    /// Destruction of the returned owner only enqueues this reserved node.
    /// It does not drop the payload or acquire that payload's resource lock.
    pub(crate) fn defer_on_drop(self, queue: &SpinLock<Pending<T>>) -> Deferred<'_, T> {
        Deferred {
            ticket: Some(self),
            queue,
        }
    }
}

pub(crate) struct Pending<T> {
    head: Option<Box<Node<T>>>,
}

impl<T> Default for Pending<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Pending<T> {
    pub(crate) const fn new() -> Self {
        Self { head: None }
    }

    pub(crate) fn push(&mut self, mut ticket: Ticket<T>) {
        ticket.0.next = self.head.take();
        self.head = Some(ticket.0);
    }

    pub(crate) fn pop(&mut self) -> Option<Ticket<T>> {
        let mut node = self.head.take()?;
        self.head = node.next.take();
        Some(Ticket(node))
    }

    pub(crate) fn reversed(mut self) -> Self {
        let mut reversed = Self::new();
        while let Some(ticket) = self.pop() {
            reversed.push(ticket);
        }
        reversed
    }
}

impl<T> Drop for Pending<T> {
    fn drop(&mut self) {
        // Detach each link before dropping it, even for a large batch.
        while self.pop().is_some() {}
    }
}

/// The queue's lifetime outlives the owner. A caller must drain its detached
/// batch in the payload's required cleanup context. This wrapper does not
/// make borrowed native PTE journals valid outside their original VM lock.
#[must_use = "dropping transfers cleanup to the queue"]
pub(crate) struct Deferred<'a, T> {
    ticket: Option<Ticket<T>>,
    queue: &'a SpinLock<Pending<T>>,
}

impl<T> Deferred<'_, T> {
    pub(crate) fn value_mut(&mut self) -> &mut T {
        self.ticket.as_mut().unwrap().value_mut()
    }

    /// Explicit completion takes responsibility back from the queue. Only
    /// call this within the payload's required resource/VM cleanup context.
    pub(crate) fn into_ticket(mut self) -> Ticket<T> {
        self.ticket.take().unwrap()
    }
}

impl<T> Drop for Deferred<'_, T> {
    fn drop(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            self.queue.lock().push(ticket);
        }
    }
}
