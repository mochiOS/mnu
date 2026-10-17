//! Snapshot bytes without moving authority; usercopy may enter the pager.
//! Commit only the same globally unique queue entry after dropping its locks.

use super::{
    IpcEndpoint, MAILBOX_CAP, MAX_THREADS, Mailbox, Message, ObjectHandleAttachments, UserReceive,
    allocate_message, endpoint_is_valid, lock_mailboxes, record_ipc_copy, release_message,
};
use alloc::boxed::Box;
use mnu_abi::status::Error;

impl Mailbox {
    fn snapshot_receive(
        &self,
        endpoint: IpcEndpoint,
        max_copy: usize,
        accept_handles: bool,
    ) -> Result<Option<(usize, Box<Message>)>, u64> {
        if self.count > MAILBOX_CAP {
            return Err(Error::BackingFailure.into_raw());
        }
        for offset in 0..self.count {
            let slot = self.queue[(self.head + offset) % MAILBOX_CAP] as usize;
            let message = self
                .slots
                .get(slot)
                .and_then(Option::as_deref)
                .ok_or_else(|| Error::BackingFailure.into_raw())?;
            if message.to != endpoint.thread_id
                || message.to_slot != endpoint.slot
                || message.to_generation != endpoint.generation
            {
                continue;
            }
            if !accept_handles && !message.object_handles.is_empty() {
                return Err(Error::LimitExceeded.into_raw());
            }
            if message.message_id == 0 || message.len > message.data.len() {
                return Err(Error::BackingFailure.into_raw());
            }
            let mut snapshot =
                allocate_message().ok_or_else(|| Error::ResourceUnavailable.into_raw())?;
            snapshot.message_id = message.message_id;
            snapshot.len = message.len.min(max_copy);
            snapshot.data[..snapshot.len].copy_from_slice(&message.data[..snapshot.len]);
            // No Handle references are cloned or published before usercopy.
            return Ok(Some((slot, snapshot)));
        }
        Ok(None)
    }

    fn commit_receive(&mut self, slot: usize, id: u64) -> Result<Box<Message>, u64> {
        if self.count > MAILBOX_CAP {
            return Err(Error::BackingFailure.into_raw());
        }
        if !self
            .slots
            .get(slot)
            .and_then(Option::as_ref)
            .is_some_and(|message| message.message_id == id)
        {
            return Err(Error::NotFound.into_raw());
        }
        if !(0..self.count)
            .any(|offset| self.queue[(self.head + offset) % MAILBOX_CAP] as usize == slot)
        {
            return Err(Error::BackingFailure.into_raw());
        }
        let count = self.count;
        for _ in 0..count {
            let queued = self
                .dequeue_slot()
                .ok_or_else(|| Error::BackingFailure.into_raw())?;
            if queued != slot {
                self.enqueue_slot(queued)
                    .map_err(|_| Error::BackingFailure.into_raw())?;
            }
        }
        self.take_slot(slot)
            .ok_or_else(|| Error::BackingFailure.into_raw())
    }
}

pub(super) fn copy_message(
    endpoint: IpcEndpoint,
    caller: u64,
    output: u64,
    max_copy: usize,
    accept_handles: bool,
) -> Result<Option<UserReceive>, u64> {
    let slot = endpoint.slot as usize;
    if slot >= MAX_THREADS {
        return Err(Error::BackingFailure.into_raw());
    }
    let prepared = {
        let boxes = lock_mailboxes();
        if !endpoint_is_valid(endpoint) {
            return Err(Error::NotFound.into_raw());
        }
        boxes[slot].snapshot_receive(endpoint, max_copy, accept_handles)?
    };
    let Some((message_slot, snapshot)) = prepared else {
        return Ok(None);
    };
    if let Err(error) = crate::syscall::copy_to_user_native(output, &snapshot.data[..snapshot.len])
    {
        release_message(snapshot);
        return Err(error.into_raw());
    }
    let committed = {
        let mut boxes = lock_mailboxes();
        if !endpoint_is_valid(endpoint) {
            Err(Error::NotFound.into_raw())
        } else {
            boxes[slot]
                .commit_receive(message_slot, snapshot.message_id)
                .map(|message| {
                    if message.expects_reply {
                        if let Some((caller_slot, generation)) =
                            crate::task::thread_slot_index_and_generation_by_u64(caller)
                        {
                            if caller_slot < MAX_THREADS {
                                boxes[caller_slot].add_reply_target(
                                    message.from,
                                    message.call_id,
                                    (caller, generation),
                                );
                            }
                        }
                    }
                    message
                })
        }
    };
    let copy_len = snapshot.len;
    release_message(snapshot);
    let mut message = committed?;
    record_ipc_copy(copy_len);
    let received = UserReceive {
        from: message.from,
        copy_len,
        expects_reply: message.expects_reply,
        call_id: message.call_id,
        object_handles: core::mem::replace(
            &mut message.object_handles,
            ObjectHandleAttachments::empty(),
        ),
    };
    release_message(message);
    Ok(Some(received))
}
