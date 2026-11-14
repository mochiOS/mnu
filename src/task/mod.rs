//! タスク管理モジュール
//!
//! マルチタスク機能を提供（プロセスとスレッドの管理）

pub(crate) mod authority_transition;
pub mod context;
pub(crate) mod deferred;
pub mod fd_table;
pub(crate) mod handle_snapshot;
pub mod handle_table;
pub mod ids;
pub(crate) mod image_origin;
pub(crate) mod image_transition;
pub(crate) mod ipc_generation;
pub mod launch_context;
pub(crate) mod memory_range;
pub(crate) mod operation;
pub(crate) mod owned_executor;
pub(crate) mod owned_work;
pub mod process;
pub mod scheduler;
pub(crate) mod stream;
pub mod thread;
pub mod usermode;

pub use context::{switch_context, switch_to_thread, Context};
pub use fd_table::{FileHandle, FileHandleCap, OpenFile};
pub use handle_table::{
    HandleRights, KernelObject, ObjectHandle, ObjectHandleEntry, ObjectHandleTable, ProviderObject,
    PROCESS_MAX_OBJECT_HANDLES,
};
pub use ids::{PrivilegeLevel, ProcessId, ProcessState, SchedulingClass, ThreadId, ThreadState};
pub use launch_context::{
    LaunchContext, PROCESS_MAX_INHERITED_HANDLES, PROCESS_MAX_INHERITED_VALUES,
};
pub use process::{
    add_process, find_process_id_by_name, flush_deferred_process_reclaims, for_each_process,
    mark_process_exited, process_count, process_has_kernel_authority,
    process_has_kernel_capability_authority, register_process_exit_waiter,
    release_process_borrowed_mappings, remove_process, remove_process_exit_waiter,
    remove_process_exit_waiters, with_process, with_process_mut, DmaBuffer, MemoryBacking,
    MemoryRegion, MmioMapping, Process, ProcessObject, ProcessTable, ResourceLimits,
};
pub use scheduler::{
    block_current_thread, exit_current_task, init_scheduler, is_scheduler_enabled,
    schedule_and_switch, scheduler_tick, sleep_thread, sleep_thread_unless_woken, start_scheduling,
    terminate_thread, wake_registered_waiter, wake_thread, yield_now,
};
pub(crate) use thread::ipc_slot_index_and_generation_by_u64;
pub use thread::{
    add_thread, allocate_kernel_stack, allocate_kernel_stack_in_table, count_threads_by_state,
    current_thread_id, current_thread_slot, for_each_thread, free_kernel_stack,
    kernel_stack_high_water_bytes, kernel_stack_table_in_use, peek_next_thread,
    prepare_kernel_stack_user_table, reclaim_current_cpu_kernel_stack, remove_thread,
    resume_process_threads, retire_current_kernel_stack, set_current_thread, set_thread_state,
    set_thread_state_at_slot, suspend_process_threads, thread_count, thread_id_exists,
    thread_slot_index, thread_slot_index_and_generation, thread_slot_index_and_generation_by_u64,
    thread_slot_index_by_u64, thread_to_process_id, with_thread, with_thread_at_slot,
    with_thread_at_slot_mut, with_thread_mut, Thread, ThreadQueue, ThreadUpcallDelivery,
    ThreadUpcallError, UserUpcallContext,
};
pub use usermode::{jump_to_usermode, resume_usermode};

/// Native execution identity, independent of syscall validation.
pub(crate) fn current_process_id() -> Option<ProcessId> {
    current_thread_id().and_then(|id| with_thread(id, |thread| thread.process_id()))
}
