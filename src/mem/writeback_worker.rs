//! Deferred VM backing writeback. Jobs retain authorized backing objects, not
//! caller virtual addresses or compatibility state. Only the bootstrap path
//! starts this execution context; user processes can submit captured ranges.
use super::{vm_object::VmObject, writeback::Batch};
use crate::task::{
    self,
    handle_table::{HandleRights, KernelObject, ObjectHandleEntry},
    owned_executor::Executor,
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use mnu_abi::status::Error;

type Work = (Batch<Arc<VmObject>>, bool);
static EXECUTOR: Executor<Work, 32> = Executor::new();
static STARTED: AtomicBool = AtomicBool::new(false);
const STACK_SIZE: usize = 32 * 1024;

pub(crate) fn start(process: task::ProcessId) -> Result<(), Error> {
    if STARTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(Error::AlreadyExists);
    }
    let Some(stack) = task::allocate_kernel_stack(STACK_SIZE) else {
        STARTED.store(false, Ordering::Release);
        return Err(Error::ResourceUnavailable);
    };
    let thread = task::Thread::new(process, "vm-writeback", run, stack, STACK_SIZE);
    let Some(thread) = task::add_thread(thread) else {
        task::free_kernel_stack(stack);
        STARTED.store(false, Ordering::Release);
        return Err(Error::ResourceUnavailable);
    };
    // Admission becomes possible only after the persistent thread is live.
    EXECUTOR.install_worker(thread.as_u64())
}

fn run() -> ! {
    loop {
        if EXECUTOR.run_one(
            |(work, refresh)| {
                work.execute(|object, offset, length| {
                    if !refresh
                        || matches!(object.object_key(), super::vm_object::ObjectKey::Memory(_))
                    {
                        return object.flush_range(offset, length);
                    }
                    let mut owner = super::extent_transaction::ExtentTransaction::prepare_refresh(
                        object, offset, length,
                    )?;
                    owner.writeback_refresh()?;
                    owner.publish_local()
                })
            },
            || {},
        ) {
            continue;
        }
        if let Some(thread) = task::current_thread_id() {
            if task::sleep_thread_unless_woken(thread) {
                task::yield_now();
            }
        } else {
            task::yield_now();
        }
    }
}

/// Reserve the result Handle before making the job executable. Handle-table
/// failure, queue pressure and missing context perform no backing I/O. The
/// caller's table is never locked during cleanup, wakeup or provider IPC.
pub(crate) fn submit(process: task::ProcessId, work: Batch<Arc<VmObject>>, refresh: bool) -> u64 {
    let submission = match Executor::<Work, 32>::prepare((work, refresh)) {
        Ok(submission) => submission,
        Err((error, _work)) => return error.into_raw(),
    };
    let receipt = submission.receipt();
    let mut submission = Some(submission);
    let mut removed = None;
    let result = task::with_process_mut(process, |process| {
        let rights = HandleRights::READ
            .union(HandleRights::WAIT)
            .union(HandleRights::DUPLICATE)
            .union(HandleRights::TRANSFER);
        let table = process.object_handles_mut();
        let handle = table
            .insert(ObjectHandleEntry::new(
                KernelObject::Completion(receipt.clone()),
                rights,
            ))
            .ok_or(Error::ResourceUnavailable)?;
        match EXECUTOR.admit(submission.take().unwrap()) {
            Ok(worker) => Ok((handle, worker)),
            Err((error, rejected)) => {
                submission = Some(rejected);
                removed = table.take_entry(handle);
                Err(error)
            }
        }
    })
    .unwrap_or(Err(Error::NotReady));
    drop(removed);
    drop(submission);
    match result {
        Ok((handle, worker)) => {
            task::wake_registered_waiter(task::ThreadId::from_u64(worker));
            handle.raw() as u64
        }
        Err(error) => error.into_raw(),
    }
}
