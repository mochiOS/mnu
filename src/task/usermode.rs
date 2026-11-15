//! Native task entry. CPU return frames and instructions stay in arch/;
//! callers retain the current process and validate its memory authority.
#[cfg(target_arch = "x86_64")]
#[path = "../arch/x86_64/task_usermode.rs"]
mod selected;
#[cfg(target_arch = "aarch64")]
#[path = "../arch/aarch64/task_usermode.rs"]
mod selected;

pub use selected::{jump_to_usermode, resume_usermode};
