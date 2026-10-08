//! タスク管理モジュール
//!
//! マルチタスク機能を提供（プロセスとスレッドの管理）

pub mod context;
pub mod fd_table;
pub mod handle_table;
pub mod ids;
pub mod launch_context;
pub mod process;
pub mod scheduler;
pub mod thread;
pub mod usermode;

pub use context::{switch_context, switch_to_thread, Context};
pub use fd_table::{FdTable, FileHandle, FileHandleCap, OpenFile, FD_BASE, PROCESS_MAX_FDS};
pub use handle_table::{
    HandleRights, KernelObject, ObjectHandle, ObjectHandleEntry, ObjectHandleTable,
    ProviderObject, PROCESS_MAX_OBJECT_HANDLES,
};
pub use ids::{PrivilegeLevel, ProcessId, ProcessState, SchedulingClass, ThreadId, ThreadState};
pub use launch_context::{
    LaunchContext, PROCESS_MAX_INHERITED_HANDLES, PROCESS_MAX_INHERITED_VALUES,
};
pub(crate) use process::ProcessCredentials;
pub use process::{
    add_process, find_process_id_by_name, flush_deferred_process_reclaims, for_each_process,
    has_child_process, mark_process_exited, process_count, process_has_kernel_authority,
    process_has_kernel_capability_authority,
    reap_zombie_child_process, register_process_exit_waiter, release_process_dma_buffers,
    release_process_mmio_mappings, remove_process, remove_process_exit_waiter,
    remove_process_exit_waiters, with_process, with_process_mut, DmaBuffer, MmapBacking, MmapRegion,
    MmioMapping, Process, ProcessObject, ProcessTable, ResourceLimits,
};
pub use scheduler::{
    block_current_thread, exit_current_task, init_scheduler, is_scheduler_enabled,
    schedule_and_switch, scheduler_tick, sleep_thread, sleep_thread_unless_woken, start_scheduling,
    terminate_thread, wake_registered_waiter, wake_thread, yield_now,
};
pub use thread::{
    add_thread, allocate_kernel_stack, allocate_kernel_stack_in_table, count_threads_by_state,
    current_thread_id, current_thread_slot, for_each_thread, free_kernel_stack,
    kernel_stack_high_water_bytes, kernel_stack_table_in_use, peek_next_thread,
    reclaim_current_cpu_kernel_stack, remap_kernel_stack_user_table, remove_thread,
    resume_process_threads, retire_current_kernel_stack, set_current_thread, set_thread_state,
    set_thread_state_at_slot, suspend_process_threads, thread_count, thread_id_exists,
    thread_slot_index, thread_slot_index_and_generation,
    thread_slot_index_and_generation_by_u64, thread_slot_index_by_u64, thread_to_process_id,
    with_thread, with_thread_at_slot, with_thread_at_slot_mut, with_thread_mut, Thread,
    ThreadQueue, ThreadUpcallDelivery, ThreadUpcallError, UserUpcallContext,
};
pub use usermode::{jump_to_usermode, jump_to_usermode_fork_child};
