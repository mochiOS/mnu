//! Process creation metadata shared by mnu and its user space.

/// Marks an environment entry in the NUL-separated process creation metadata.
pub const ENVIRONMENT_PREFIX: &str = "__MNU_EXEC_ENV=";

/// Assigns an opaque security identity to a new process.
///
/// mnu uses this identity only for generic isolation mechanisms. The user space
/// that launches the process decides what the identity represents.
pub const SECURITY_IDENTITY_PREFIX: &str = "__MNU_EXEC_SECURITY_IDENTITY=";
