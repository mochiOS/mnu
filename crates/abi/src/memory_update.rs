//! HandleControl operations for a private provider-memory update owner.
//! Codes are scoped to this object type; no filesystem or POSIX policy.
//! Unknown codes or nonempty arguments return native InvalidArgument; a busy
//! control owner returns native NotReady without changing transaction state.

/// Record uncertainty before issuing external mutation. Losing this owner
/// afterward quarantines backing data rather than restoring old mappings.
pub const BEGIN: u64 = 1;
/// The provider confirms that external storage is unchanged. An I/O error
/// alone is not such confirmation; a partial mutation must not use this code.
pub const UNCHANGED: u64 = 2;
/// The provider confirms that the requested new extent is authoritative.
/// An error after this decision retains publication intent for cleanup retry.
pub const PUBLISH: u64 = 3;
