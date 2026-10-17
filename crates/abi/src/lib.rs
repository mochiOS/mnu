#![no_std]

/// ブートローダーからmnuへ渡す起動情報のABIです。
pub mod boot;

/// Canonical metadata for named capabilities shared by kernel and user space.
pub mod capability;
pub mod completion;
pub mod diagnostic;
pub mod handle_snapshot;
pub mod memory_map;
pub mod memory_copy;
pub mod memory_update;
pub mod status;

/// プロセス作成時に渡すメタデータのABIです。
pub mod exec;

/// ハイパーバイザーのDomainとして起動するときに使うABIです。
pub mod hypervisor;

/// mnuの性能計測結果をユーザー空間へ渡す固定ABIです。
pub mod performance;

/// Relocatable initial-stack image for native process image replacement.
pub mod process_image;
pub mod process_create;

/// Generic user-space-backed object operation protocol.
pub mod provider;

/// Grantで共有するrequest/response ringの固定ABIです。
pub mod shared_ring;

/// Generic access permissions accepted by [`SyscallNumber::MemoryProtect`].
///
/// These are native VM permissions, not POSIX `PROT_*` values. Compatibility
/// layers must translate their public protection flags before entering mnu.
pub const MEMORY_ACCESS_READ: u64 = 1 << 0;
pub const MEMORY_ACCESS_WRITE: u64 = 1 << 1;
pub const MEMORY_ACCESS_EXECUTE: u64 = 1 << 2;
pub const MEMORY_ACCESS_ALL: u64 = MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE | MEMORY_ACCESS_EXECUTE;

/// Native VM mapping options. A zero backing handle creates anonymous memory;
/// a nonzero handle names a mappable kernel object.
pub const MEMORY_MAP_EXACT: u64 = 1 << 0;
pub const MEMORY_MAP_SHARED: u64 = 1 << 1;
/// Replace existing ordinary mappings at the exact requested virtual range.
/// Requires EXACT; borrowed device/DMA mappings cannot be overwritten.
pub const MEMORY_MAP_REPLACE: u64 = 1 << 2;
pub const MEMORY_MAP_OPTIONS_ALL: u64 = MEMORY_MAP_EXACT | MEMORY_MAP_SHARED | MEMORY_MAP_REPLACE;
/// Byte-sized RAM backing whose creator receives CONTROL for extent changes.
/// Zero options retain fixed, nonempty, page-aligned creation.
pub const MEMORY_OBJECT_RESIZABLE: u64 = 1;
/// Queue captured VM backing ranges and return a read-only completion Handle.
/// With zero options, MemorySync remains blocking and returns zero on success.
/// The completion supports READ, WAIT, DUPLICATE and TRANSFER, not mutation.
pub const MEMORY_SYNC_DEFERRED: u64 = 1;
/// Refresh shared backing aliases after writeback, preserving private/COW
/// bytes. Requires DEFERRED and retained READ authority on every selected
/// shared backing. Dirty bytes use their original retained writer references,
/// never authority borrowed from a read-only alias. Errors retain rollback.
pub const MEMORY_SYNC_REFRESH: u64 = 1 << 1;

/// mnu native syscall numbers.
/// An unregistered number returns status::Error::Unsupported; compatibility
/// environments select their own meaning and never gain a legacy fallback.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    // Native mnu file syscalls
    /// Sends one message to an opaque endpoint. Failures use status::Error:
    /// NotReady for queue pressure, ResourceUnavailable for allocation failure.
    IpcSend = 514,
    /// Nonblocking receive. Empty queues return status::Error::NotReady;
    /// all other admission and delivery failures also use status::Error.
    IpcRecv = 515,
    Sleep = 517,
    FindProcessByName = 518,
    /// Reads one 1/2/4-byte port value under the caller's device authority.
    /// Ports must fit u16; selector and authority failures use status::Error.
    PortIn = 520,
    /// Writes the low width bytes under the same native port contract.
    PortOut = 521,
    /// Copies native display geometry. Backend and usercopy failures retain
    /// status::Error categories rather than selecting a POSIX errno.
    GetFramebufferInfo = 528,
    /// Maps borrowed display storage under display authority. Validation,
    /// allocation, capacity and VM failures use status::Error.
    MapFramebuffer = 529,
    /// Blocking receive; native failures never report an empty wakeup.
    IpcRecvWait = 533,
    /// Maps authorized borrowed MMIO, never allocator-owned RAM. Native
    /// failures distinguish AccessDenied, AlreadyExists, LimitExceeded,
    /// ResourceUnavailable and NotReady; no POSIX errno is returned.
    MapPhysicalRange = 536,
    /// Validates an opaque endpoint's live generation. Missing or stale
    /// endpoints return status::Error::NotFound.
    IpcEndpointAlive = 551,
    /// Copies complete native process-inspection records under caller authority.
    /// A zero record capacity returns zero without copying. Failures before
    /// the first complete record use status::Error; later faults return the
    /// completed prefix. No task-table lock is retained across usercopy.
    ListProcesses = 552,
    /// Returns 1/0 for authority of an IPC-resolved sender. Input, allocation
    /// and usercopy failures use status::Error; an absent sender returns 0.
    CheckThreadCapability = 553,
    /// Transfers aligned sectors under device authority. Local validation,
    /// allocation and usercopy failures use status::Error. Driver status is
    /// returned unchanged; an unavailable backend is NotReady.
    BlockRead = 555,
    /// Copies all input before invoking the driver, with BlockRead's native
    /// failure contract. Transfers are bounded to 256 KiB.
    BlockWrite = 556,
    /// Returns the endpoint's native process identity. Requires ProcessInspect;
    /// failures use status::Error, never POSIX process or errno semantics.
    IpcEndpointOwner = 557,
    /// Terminates the caller's process, preserving all 64 bits of the opaque
    /// terminal value. Compatibility layers interpret their own exit status.
    ProcessExit = 574,
    ThreadCreate = 577,
    ThreadExit = 578,
    ThreadYield = 579,
    /// Maps a byte range using native placement, sharing and Handle authority.
    /// Local failures use status::Error; Provider failures remain opaque.
    /// In particular, an occupied exact range is AlreadyExists, an unusable
    /// virtual range InvalidAddress, and overflowing byte geometry LimitExceeded.
    MemoryMap = 582,
    MemoryUnmap = 583,
    /// Changes access within the caller's existing mappings. Failures use
    /// status::Error; compatibility layers select operation-specific errno.
    MemoryProtect = 584,
    /// Synchronizes owned shared backing ranges. Zero options block; native
    /// MEMORY_SYNC_DEFERRED returns a completion Handle after queue admission.
    MemorySync = 586,
    /// Creates or obtains the caller thread's opaque endpoint identifier.
    /// Failures use status::Error, not compatibility errno values.
    IpcCreate = 587,
    IpcCall = 588,
    IpcReply = 589,
    /// Receives from the caller's queue or a caller-owned endpoint. Native
    /// NotReady indicates an empty queue only for the nonblocking form.
    IpcWait = 590,
    /// Validates caller authority, including implication, without adding a
    /// grant. Input, authority and context failures use status::Error.
    CapClone = 591,
    /// Removes only an exact caller grant. An absent grant is AccessDenied;
    /// a missing execution context is NotReady. Failures use status::Error.
    CapDrop = 592,
    CapTransfer = 593,
    /// Returns 1/0 for caller authority. Input and usercopy failures use
    /// status::Error; a missing caller context is NotReady.
    CapQuery = 594,
    /// Replaces an exact caller authority with an implied narrower authority.
    /// Input failures leave the original set unchanged; local failures use
    /// status::Error. The locked replacement itself needs no allocation.
    CapRestrict = 595,
    TimeNow = 600,
    /// Allocates caller-owned DMA bytes. Local input, backing, allocation and
    /// usercopy failures use status::Error, without compatibility errno.
    DmaAlloc = 604,
    /// Revokes caller-owned DMA mappings before recycling frames. A failed
    /// revocation retains the ownership record and returns a native failure.
    DmaFree = 605,
    RandomFill = 607,
    /// Snapshots bounded user pixels before platform I/O. Authority, size,
    /// allocation, usercopy and transport failures use status::Error.
    PresentFramebuffer = 610,
    /// Native authority/transport/usercopy failures use status::Error. The
    /// platform's response status remains opaque in StorageControlResponse.
    StorageControl = 611,
    /// Copies the supported prefix of the versioned performance snapshot under
    /// profile authority. Failures use status::Error; a build without sampling
    /// returns Unsupported rather than a retryable NotReady.
    PerformanceSnapshot = 612,
    /// Positive byte limit, or a native authority/backend failure.
    FramebufferTransferLimit = 613,
    /// Commits display storage under display authority. Validation and
    /// platform failures use status::Error without errno translation.
    CommitFramebuffer = 614,
    /// StorageControl's mechanism with an explicit, bounded authority name.
    DeviceControl = 615,
    AuthorizeExec = 616,
    GetThreadSecurityContext = 617,
    BootSystemSlot = 618,
    /// Flushes under device authority. Local failures are native; driver
    /// status is opaque, and an unavailable backend returns NotReady.
    BlockFlush = 619,
    /// Copies the boot-supplied ESP GUID. Failures use status::Error: missing
    /// boot context is NotReady; a legacy/missing identity is Unsupported.
    BootEspGuid = 620,
    /// Discards one reference from the caller's table and removes inherited
    /// aliases to that selector. Requires no resource right; does not revoke
    /// other references. Failures use status::Error: invalid/missing selector
    /// is InvalidArgument, absent execution context is NotReady.
    HandleClose = 626,
    /// Adds a caller-local reference with a subset of the source rights.
    /// Requires DUPLICATE; never grants missing rights. Native failures:
    /// InvalidArgument for selectors/rights, AccessDenied for authority,
    /// ResourceUnavailable for table capacity, NotReady for missing context.
    HandleDuplicate = 627,
    /// Borrows a selector already owned by the caller, without duplication.
    /// Native failures: NotFound (key), InvalidArgument (stale selector),
    /// NotReady (execution context). Keys remain opaque to the kernel.
    LaunchHandleGet = 628,
    /// Creates a caller-local endpoint reference. SEND/RECEIVE/WAIT are
    /// bounded by existing IPC capabilities. Failures use status::Error.
    IpcCreateHandle = 629,
    /// Sends a message with attenuated object references. Admission, transfer
    /// validation and message delivery failures all use status::Error.
    IpcSendObjectHandles = 630,
    /// Handle-aware receive with native failure categories and unpublished
    /// reference reservation. Nonblocking empty queues return NotReady.
    IpcRecvObjectHandles = 631,
    IpcCallObjectHandles = 632,
    IpcReplyObjectHandles = 633,
    HandleRead = 634,
    HandleWrite = 635,
    /// Moves a provider cursor using native HANDLE_SEEK_* bases and a signed
    /// displacement. Successful positions are at most i64::MAX. Mechanism
    /// failures use status::Error; provider status is passed through.
    HandleSeek = 636,
    /// Creates an opaque provider reference under a caller-owned RECEIVE
    /// endpoint. Failures use status::Error; duplicate identities within that
    /// endpoint namespace are AlreadyExists, not compatibility errno values.
    ProviderObjectCreate = 637,
    /// Identifies a caller-held provider reference only on its exact owning
    /// endpoint thread/slot/generation. No particular resource rights required.
    /// Failures use status::Error: invalid selector/kind is InvalidArgument,
    /// foreign endpoint is AccessDenied, absent execution context is NotReady.
    ProviderObjectIdentify = 638,
    /// Copies all scalar bits to caller storage; the return value is status.
    /// Native failures: NotFound (key), NotReady (execution context), or the
    /// native usercopy failure. No output copy is attempted for a missing key.
    LaunchValueGet = 639,
    ClockRead = 640,
    /// Retains an endpoint owner's Process under ProcessInspect authority;
    /// SIGNAL additionally requires ProcessKill. Failures use status::Error.
    ProcessHandleOpen = 641,
    /// Observes a retained WAIT Process Handle, including after its process
    /// table record is reclaimed. Failures use status::Error.
    ProcessHandleStatus = 642,
    /// Waits on the retained target of a WAIT Process Handle. Poll/deadline
    /// expiry or a deliverable upcall returns native NotReady. Storage or
    /// deadline admission failure is ResourceUnavailable. Other failures also
    /// use status::Error; no child relationship or POSIX wait status is used.
    ProcessHandleWait = 643,
    /// Operates on a SIGNAL Process Handle. Failures use status::Error;
    /// a retired/missing target is NotFound.
    ProcessHandleResume = 645,
    /// Elects one terminal publication owner through a SIGNAL Process Handle.
    /// Native NotReady denotes an in-progress owner, NotFound a terminal or
    /// absent target. Committed exit is not undone by deferred cleanup errors.
    ProcessHandleTerminate = 646,
    /// Observes readiness through caller-owned WAIT Handles. Failures use
    /// status::Error: no ready object/deadline expiry/upcall is NotReady;
    /// local wait-storage exhaustion is ResourceUnavailable. Invalid target
    /// kind or interests is InvalidArgument, a retired endpoint is NotFound.
    /// Resource-specific native failures are preserved.
    /// Target identity is fixed during admission; selector authority is
    /// revalidated, and close/reuse cannot redirect the pending wait.
    HandleWaitMany = 647,
    /// Associates an opaque key with an existing caller-owned Handle. Does
    /// not duplicate, transfer or change rights. Native failures are
    /// InvalidArgument (selector), ResourceUnavailable (context storage),
    /// and NotReady (execution context).
    ContextHandleSet = 648,
    StreamPairCreate = 649,
    /// Reads shared native I/O behavior through a caller-owned CONTROL Handle.
    /// Failures use status::Error: InvalidArgument for selector/object kind,
    /// AccessDenied for missing CONTROL, NotReady for absent caller context.
    HandleOptionsGet = 650,
    /// Replaces shared I/O behavior, not descriptor-local flags. Unknown
    /// HANDLE_OPTIONS_ALL bits fail with native InvalidArgument before lookup;
    /// selector, authority and context failures match HandleOptionsGet.
    HandleOptionsSet = 651,
    /// Waits on a naturally aligned caller memory value using a native
    /// deadline. Failures use status::Error; successful AddressWaitResult
    /// values distinguish wakeup, predicate change and deadline completion.
    WaitOnAddress = 652,
    /// Wakes subscribers sharing the validated memory identity. Returns a
    /// count, or status::Error; a zero maximum succeeds without dereferencing.
    WakeAddress = 653,
    /// Configures the current thread's generic callback and optional defer
    /// word. Failures use status::Error; active delivery is native NotReady.
    /// Input/defer-word/stack-copy failures preserve their native categories.
    ThreadUpcallInstall = 654,
    /// Requests return through the calling thread's active token. Native
    /// failures are InvalidArgument (token) and NotReady (execution context).
    ThreadUpcallReturn = 655,
    /// Retains the calling thread with WAIT/SIGNAL/DUPLICATE/TRANSFER rights.
    /// Native failures: NotReady (caller context), ResourceUnavailable (table).
    ThreadHandleCreate = 656,
    /// Queues an opaque payload through a caller-owned SIGNAL Thread Handle.
    /// Native failures: InvalidArgument (selector/kind), AccessDenied (rights),
    /// NotReady (caller), NotFound (retired target), ResourceUnavailable (queue).
    ThreadInterrupt = 657,
    /// Writes native lifecycle metadata through a caller-owned WAIT Handle.
    /// A retired target is native NotFound, not a POSIX ESRCH. Other failures
    /// use status::Error, including native output-copy errors.
    ThreadHandleStatus = 658,
    /// Retains a Process by native identity with the same capability gates as
    /// ProcessHandleOpen. Missing targets are native NotFound; absent caller
    /// context is NotReady, and Handle storage failure is ResourceUnavailable.
    ProcessHandleOpenById = 659,
    /// Early diagnostic bytes, never a POSIX stream. Empty writes need no
    /// buffer; extent, allocation and usercopy failures use status::Error.
    DebugWrite = 660,
    /// Removes an opaque Handle association, not its owned reference.
    /// Missing keys succeed; absent execution context is native NotReady.
    ContextHandleRemove = 661,
    /// Replaces an opaque scalar without interpreting its bits. Native
    /// failures are ResourceUnavailable (storage) and NotReady (context).
    ContextValueSet = 662,
    /// Missing keys succeed; absent execution context is native NotReady.
    ContextValueRemove = 663,
    /// Reads the caller's reference rights, including an empty rights set.
    /// Requires possession only. Native failures are InvalidArgument for an
    /// invalid/missing selector and NotReady for absent execution context.
    HandleRightsGet = 664,
    ProcessImageReplace = 665,
    /// Compares two caller-held references without publishing a global ID.
    /// Both selectors are validated under the caller's Handle-table lock;
    /// no resource rights are required. Returns exactly zero or one.
    /// Failures use status::Error: invalid/missing selectors are
    /// InvalidArgument; absent execution context is NotReady.
    HandleSameObject = 666,
    /// Updates readiness bits in the calling endpoint's provider namespace.
    /// Failures use status::Error: unsupported/overlapping bits or unknown
    /// local identity is InvalidArgument; absent execution context is NotReady.
    ProviderObjectSignal = 667,
    /// Bounded opaque provider control, or native memory-update control.
    /// Mechanism failures use status::Error; provider status is passed through.
    HandleControl = 668,
    /// Suspends the caller's process until resumed. Absent execution context
    /// or no eligible thread returns native NotReady; success requires observing
    /// that the calling thread is no longer suspended.
    ProcessSuspendCurrent = 669,
    /// Suspends execution through a SIGNAL Process Handle. Failures use
    /// status::Error; no eligible thread is NotReady, a retired target NotFound.
    ProcessHandleSuspend = 670,
    /// Creates zero-filled RAM backing and returns a process-local Handle.
    /// Arguments: byte length, options. Zero options select fixed nonempty
    /// page-aligned backing; MEMORY_OBJECT_RESIZABLE permits byte extents,
    /// including zero, and grants CONTROL for MemoryObjectResize.
    /// Failures use status::Error, not compatibility-layer errno values.
    MemoryObjectCreate = 671,
    /// Returns the byte length of a process-local MemoryObject with MAP rights.
    /// Failures use status::Error. Invalid Handle selectors or object kinds
    /// are InvalidArgument; missing MAP authority is AccessDenied.
    MemoryObjectLength = 672,
    /// Reads bytes at an explicit object offset without moving its cursor.
    /// Arguments: Handle, destination, byte length, unsigned object offset.
    /// Mechanism failures use status::Error; successful prefixes are retained.
    HandleReadAt = 673,
    /// Writes bytes at an explicit object offset without moving its cursor.
    /// Arguments: Handle, source, byte length, unsigned object offset.
    /// Mechanism failures use status::Error; successful prefixes are retained.
    HandleWriteAt = 674,
    /// Writes an available prefix to a stream. Arguments: Handle, source,
    /// length, per-call options. STREAM_WRITE_COMPLETE requests all-or-none.
    StreamWrite = 675,
    /// Creates a stopped process from an authorized image Handle and serialized
    /// process_create metadata. Returns a retained WAIT/SIGNAL Process Handle.
    /// Arguments: image Handle, metadata pointer, byte length.
    /// Metadata may select a caller-owned CONTROL Handle-table capture as the
    /// source of explicit grants; it never names a foreign process table.
    ProcessCreate = 676,
    /// Reads the calling native execution context, not POSIX credentials.
    /// Arguments: output pointer and exact ExecutionIdentity byte length.
    ExecutionIdentityRead = 677,
    /// Inspects a generation-checked IPC endpoint, never a supplied PID/TID.
    /// Requires ProcessInspect. Arguments: output pointer, exact
    /// ExecutionIdentity byte length, nonzero IPC endpoint.
    IpcEndpointIdentityRead = 678,
    /// Clones only the current address space into a detached image Handle.
    /// No arguments. Requires process.spawn; no process or thread is created.
    /// Sibling execution contexts are temporarily quiesced; borrowed MMIO
    /// mappings cannot be captured.
    /// Failures use status::Error, never POSIX errno values.
    AddressSpaceClone = 679,
    /// Reads metadata for the caller's own Handle table. No object references
    /// are acquired. Arguments: HandleInfo buffer, record capacity. (0, 0)
    /// queries the current count without allocating. Failures use status::Error;
    /// an insufficient record capacity returns LimitExceeded without copying.
    HandleTableRead = 680,
    /// Reads available stream bytes. Arguments: Handle, destination, length,
    /// per-call options. STREAM_IO_TRY never changes shared object options.
    StreamRead = 681,
    /// Waits on object readiness with an entry precondition. Arguments:
    /// HandleWaitItem array, count, deadline, nonzero HandleWaitGuard pointer
    /// (zero returns InvalidArgument). Uses HandleWaitMany's native errors;
    /// a changed precondition returns NotReady.
    HandleWaitManyGuarded = 682,
    /// Reads native CPU execution accounting. Arguments: Process Handle (zero
    /// selects only the caller), output pointer, exact ProcessExecutionUsage
    /// byte length. A nonzero handle must grant WAIT; no PID is accepted.
    /// Failures use status::Error; unavailable caller/rate is NotReady.
    /// Output-copy failures retain their native categories.
    ProcessExecutionRead = 683,
    /// Waits on a memory value with a second 64-bit entry precondition.
    /// Arguments: address, expected, value size, monotonic deadline,
    /// nonzero AddressWaitGuard pointer. WakeAddress on either value releases
    /// the same waiter. Neither value carries kernel-interpreted policy.
    /// Failures use status::Error, including copying the guard descriptor.
    WaitOnAddressGuarded = 684,
    /// Describes one native clock without reading its timestamp. Arguments:
    /// ClockId, ClockInfo output pointer, exact ClockInfo byte length.
    ClockDescribe = 685,
    /// Changes the byte extent of RAM backing selected by a caller-owned
    /// Handle granting CONTROL. Arguments: Handle, new length. Revokes live
    /// and detached aliases before reclaiming or zeroing backing storage.
    /// Failures use status::Error. Invalid Handle selectors or object kinds
    /// are InvalidArgument; missing CONTROL authority is AccessDenied.
    MemoryObjectResize = 686,
    /// Read a bounded diagnostic byte history. Requires diagnostics.read.
    /// Arguments: absolute cursor, byte buffer, byte capacity, diagnostic
    /// ReadResult output pointer. Returns copied bytes; never consumes history.
    DiagnosticRead = 687,
    /// Read the current thread's interrupted context using its active upcall
    /// token. Arguments: token, output pointer, exact ThreadUpcallSnapshot size.
    /// No PID, thread Handle, or caller-supplied return context is accepted.
    /// Failures use status::Error. Failed copies do not consume the token.
    ThreadUpcallInspect = 688,
    /// Return to an explicitly selected user context. Arguments: active token,
    /// ThreadUpcallSnapshot pointer, exact byte length. Validation and commit
    /// are atomic; invalid input leaves delivery and saved state unchanged.
    /// Failures use status::Error, preserving native input-copy failures.
    ThreadUpcallReturnContext = 689,
    /// Replace only the calling thread's user CPU context, without an upcall
    /// token. Arguments: ThreadUpcallSnapshot pointer, exact byte length.
    /// Validates user addresses, flags and CPU-supported x87/SSE state before
    /// committing. An active upcall or pending restoration is native NotReady.
    /// Other failures use status::Error, including native input-copy failures.
    /// Does not change TLS, Handles, credentials, or another thread's state.
    ThreadContextRestore = 690,
    /// Samples strong references to an object owned by the calling endpoint.
    /// Argument: provider-owned object ID (not a Handle or process ID). Counts
    /// Handles, IPC attachments, VM aliases and temporary kernel references;
    /// excludes only this query's temporary reference. Weak registrations do
    /// not count. Only the exact creating endpoint thread/slot/generation may
    /// inspect its namespace. A sample is not a lifetime pin or revocation.
    /// Failures use `status::Error`: absent execution context is NotReady;
    /// invalid or unknown namespace-local identities are InvalidArgument.
    ProviderObjectReferenceCount = 691,
    /// Reads public logical processor counts. Arguments: ProcessorInfo output
    /// pointer and exact byte length. No scheduling or compatibility policy.
    /// Failures use status::Error. Missing or inconsistent boot/online counts
    /// are NotReady, never an invented single-processor result.
    ProcessorDescribe = 692,
    /// Captures references from the caller's own Handle table. No arguments.
    /// Returns a private READ/CONTROL/DUPLICATE Handle, without TRANSFER.
    /// HandleReadAt reads immutable handle_snapshot metadata; ProcessCreate
    /// may explicitly select it as its captured grant source.
    /// Failures use status::Error. Capture allocation or a full caller table
    /// returns ResourceUnavailable without publishing a partial capture.
    HandleTableCapture = 693,
    /// Writes to a provider with a per-operation exclusive byte end. Arguments:
    /// WRITE Handle, source pointer, byte length, byte end. Provider selects
    /// its current position and allowed prefix in one operation; no cursor
    /// query or persisted policy is involved. STATUS_BOUND_REACHED means no
    /// nonempty prefix fits. Other objects/providers may reject the operation.
    HandleWriteBounded = 694,
    /// Maps with a caller-supplied per-operation virtual-byte ceiling. Args:
    /// memory_map::Request pointer, exact REQUEST_LEN. The request is copied
    /// before VM locking; live usage and insertion are one atomic operation.
    /// Same authority and placement rules as MemoryMap; stores no policy.
    MemoryMapBounded = 695,
    /// Replaces the caller's image with a per-operation virtual-byte ceiling.
    /// Arguments: image Handle, opaque authorization identity pointer/length,
    /// startup image pointer/length, byte ceiling. Same authority and input
    /// validation as ProcessImageReplace. Counts the prepared target's image,
    /// stack, TLS and reservations, not the old address space. A rejected
    /// target leaves the current image and sibling threads intact. No policy
    /// or resource-limit identity is interpreted or stored by this operation.
    ProcessImageReplaceBounded = 696,
    /// Prepares an owned provider-memory extent update. Arguments: caller-local
    /// endpoint RECEIVE Handle, nonzero memory identity, old length, new length,
    /// optional admission Handle (zero for immediate, unordered admission).
    /// Endpoint authority scopes the identity; no PID/FD/path or provider RPC.
    /// Suspends all matching mappings and acknowledges remote TLBs before
    /// returning a private CONTROL-only Handle (no TRANSFER or DUPLICATE).
    /// HandleControl(memory_update::*) resolves the outcome with empty payloads.
    /// Close before BEGIN cancels; close after BEGIN without confirmation
    /// quarantines backing data. No external mutation may precede BEGIN.
    /// Local authority, allocation and publication failures use status::Error.
    ProviderMemoryUpdateCreate = 697,
    /// Registers a cancellable FIFO position for a provider's memory identity.
    /// Args: caller-local endpoint RECEIVE Handle, nonzero memory identity.
    /// Returns WAIT|TRANSFER only. Readable means a retry can consume it; peer
    /// closed means consumed/unavailable. It grants no mutation permission.
    /// Failures use status::Error; invalid/stale endpoint selectors are
    /// InvalidArgument and absent RECEIVE authority is AccessDenied.
    ProviderMemoryAdmissionCreate = 698,
    /// Copies a bounded byte snapshot between two addresses in the caller's
    /// current address space. Args: destination, source, byte length. Returns
    /// the copied length; at most memory_copy::MAX_BYTES per operation.
    /// Both ranges require their existing user mapping permissions. No other
    /// process, Handle, permission changes or caller-specific policy is involved.
    /// Zero length accesses neither pointer. Overlap is supported within one
    /// snapshot; failure may leave a destination prefix changed, never rollback.
    MemoryCopy = 699,
    CheckGravityExist = 999,
}

/// Logical processors configured at boot and currently online. Read-only
/// discovery does not grant affinity, scheduling or resource-control rights.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessorInfo {
    pub configured: u32,
    pub online: u32,
    /// Always zero; readers must reject unknown extensions.
    pub reserved: [u32; 2],
}

pub const PROCESS_STATE_RUNNING: u32 = 1;
/// Native process inspection record: identity, lifecycle and resource metrics.
/// POSIX parentage is not part of this kernel ABI.
pub const PROCESS_INFO_RECORD_SIZE: usize = 104;

/// Native object identities for a caller or authenticated IPC endpoint.
/// These identifiers grant no authority and carry no uid/gid, parent, session
/// or application metadata.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExecutionIdentity {
    pub process_id: u64,
    pub thread_id: u64,
}

/// Native execution domains and their sampling rate. No parent/child, uid,
/// process group, POSIX clock units, or policy-layer aggregation is included.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessExecutionUsage {
    pub user_ticks: u64,
    pub kernel_ticks: u64,
    pub ticks_per_second: u64,
    pub reserved: u64,
}
pub const PROCESS_STATE_EXITED: u32 = 2;
/// Poll without sleeping when passed as a `HandleWaitMany` deadline.
pub const HANDLE_WAIT_POLL: u64 = 0;
/// Wait without a deadline when passed to `HandleWaitMany`.
pub const HANDLE_WAIT_INFINITE: u64 = u64::MAX;
pub const PROCESS_WAIT_POLL: u64 = HANDLE_WAIT_POLL;
pub const PROCESS_WAIT_INFINITE: u64 = HANDLE_WAIT_INFINITE;

/// Two process-local endpoints of a native unidirectional byte stream.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamPair {
    pub read: u32,
    pub write: u32,
}

/// Native process lifetime state. `exit_code` is the value supplied to
/// `ProcessExit`; POSIX wait-status encoding belongs in user space.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessStatus {
    pub process_id: u64,
    pub state: u32,
    pub reserved: u32,
    pub exit_code: u64,
}

/// Initial userspace register state for a native thread.
///
/// This structure contains mechanism only. Language runtimes may use
/// `thread_local_base` for their own TLS ABI; the kernel does not interpret
/// the memory it points to.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThreadCreateContext {
    pub entry: u64,
    pub stack_pointer: u64,
    pub argument: u64,
    pub thread_local_base: u64,
    pub flags: u64,
    pub reserved: [u64; 3],
    pub registers: ThreadInitialRegisters,
}

/// Metadata for an already-owned native Handle. The table may change after
/// this observation; transfer and creation must revalidate the live reference.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandleInfo {
    pub handle: u32,
    pub reserved: u32,
    pub rights: u64,
}

/// Remaining x86-64 general registers at initial entry. RDI is `argument` and
/// RSP is `stack_pointer`. Segment selectors and privileged flags are not
/// caller-controlled; new threads start with interrupts enabled and IOPL zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThreadInitialRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// Read-only x86-64 context captured before entering a native upcall.
/// RDI is `argument`; the remaining GPRs use the native thread register layout.
/// `fx_state` is the 512-byte FXSAVE64 image (x87/SSE, not AVX/XSAVE).
/// Editing the copy alone does not change the kernel's return context. It may
/// be supplied to ThreadUpcallReturnContext for an active delivery, or to
/// ThreadContextRestore for an independent self continuation. Both validate
/// user CPU state atomically and leave TLS and execution authority unchanged.
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadUpcallSnapshot {
    pub instruction: u64,
    pub stack_pointer: u64,
    pub rflags: u64,
    pub argument: u64,
    pub registers: ThreadInitialRegisters,
    pub fx_state: [u8; 512],
}

const _: () = assert!(core::mem::size_of::<ThreadUpcallSnapshot>() == 656);
const _: () = assert!(core::mem::offset_of!(ThreadUpcallSnapshot, fx_state) == 144);

/// Opt in to synchronous user exception delivery on this thread's upcall stack.
pub const THREAD_UPCALL_EXCEPTIONS: u64 = 1;
pub const THREAD_UPCALL_KIND_INTERRUPT: u64 = 0;
pub const THREAD_UPCALL_KIND_EXCEPTION: u64 = 1;

/// Generic VM failure information; language runtimes choose their own policy.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryFaultCause {
    Unmapped = 1,
    AccessDenied = 2,
    OutsideBacking = 3,
    BackingFailure = 4,
    ResourceUnavailable = 5,
    Unresolved = 6,
}

/// User-space entry point and private stack for a native thread upcall.
///
/// The kernel treats `payload` values as opaque. The entry point receives the
/// payload in the first argument register and a one-shot return token in the
/// second argument register. It must finish with `ThreadUpcallReturn` rather
/// than returning normally.
/// The third argument identifies INTERRUPT (opaque payload) or EXCEPTION.
/// With THREAD_UPCALL_EXCEPTIONS enabled, an x86-64 page fault supplies vector
/// 14 as payload, fault address as argument four, CPU error code as argument
/// five, the faulting instruction address as argument six, and a
/// `MemoryFaultCause` value as argument seven (on the x86-64 C ABI stack).
/// Return retries
/// the original instruction; recursive exceptions while active are not queued.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThreadUpcallConfig {
    pub entry: u64,
    pub stack_base: u64,
    pub stack_size: u64,
    pub flags: u64,
    /// Optional aligned user AtomicU32. Nonzero contents defer asynchronous
    /// callbacks without consuming their queue. An unreadable word also
    /// defers; synchronous exceptions and token returns are unaffected.
    pub defer_word: u64,
    pub reserved: [u64; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThreadStatus {
    pub thread_id: u64,
    pub process_id: u64,
    pub state: u32,
    pub reserved: u32,
}

pub const THREAD_STATE_READY: u32 = 1;
pub const THREAD_STATE_RUNNING: u32 = 2;
pub const THREAD_STATE_BLOCKED: u32 = 3;
pub const THREAD_STATE_SLEEPING: u32 = 4;
pub const THREAD_STATE_TERMINATED: u32 = 5;

/// A process-local object handle and the signals a caller wants to observe.
///
/// `observed` is written by `HandleWaitMany`. Signal meanings describe native
/// object lifecycle/readiness and are intentionally independent of POSIX.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandleWaitItem {
    pub handle: u32,
    /// Optional free-byte threshold for a stream WRITABLE interest. Zero uses
    /// ordinary readiness; other object kinds do not accept this parameter.
    pub minimum_write_bytes: u32,
    pub interests: u64,
    pub observed: u64,
}

/// An entry precondition on a readable, aligned word in the caller's memory.
/// The wait returns without sleeping when its value differs from `expected`.
/// Writers must call WakeAddress after publishing a changed value. Guard
/// admission and wakeups share the address wait queue, so a notification
/// racing with admission cannot be lost.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandleWaitGuard {
    pub address: u64,
    pub expected: u64,
}

/// A 64-bit memory precondition, shared by address and object waits.
/// Writers must call WakeAddress after publishing a changed value.
pub type AddressWaitGuard = HandleWaitGuard;

pub const HANDLE_SIGNAL_TERMINATED: u64 = 1 << 0;
pub const HANDLE_SIGNAL_READABLE: u64 = 1 << 1;
pub const HANDLE_SIGNAL_WRITABLE: u64 = 1 << 2;
pub const HANDLE_SIGNAL_PEER_CLOSED: u64 = 1 << 3;
/// The object has no queued or in-flight work that must complete first.
pub const HANDLE_SIGNAL_IDLE: u64 = 1 << 4;
pub const HANDLE_WAIT_MANY_MAX_ITEMS: usize = 64;

/// Native result returned by `WaitOnAddress`.
///
/// POSIX errno translation deliberately belongs in user space.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressWaitResult {
    Awoken = 0,
    ValueChanged = 1,
    DeadlineReached = 2,
}

impl AddressWaitResult {
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            x if x == Self::Awoken as u64 => Some(Self::Awoken),
            x if x == Self::ValueChanged as u64 => Some(Self::ValueChanged),
            x if x == Self::DeadlineReached as u64 => Some(Self::DeadlineReached),
            _ => None,
        }
    }
}

/// Wait without a deadline when passed to `WaitOnAddress`.
pub const ADDRESS_WAIT_INFINITE: u64 = u64::MAX;

/// Kernel-provided clocks. These values are native mnu ABI selectors and are
/// intentionally distinct from POSIX `clockid_t` values.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockId {
    Realtime = 0x4d4e_5543_4c4b_0001,
    Monotonic = 0x4d4e_5543_4c4b_0002,
    ProcessCpu = 0x4d4e_5543_4c4b_0003,
    ThreadCpu = 0x4d4e_5543_4c4b_0004,
}

impl ClockId {
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            x if x == Self::Realtime as u64 => Some(Self::Realtime),
            x if x == Self::Monotonic as u64 => Some(Self::Monotonic),
            x if x == Self::ProcessCpu as u64 => Some(Self::ProcessCpu),
            x if x == Self::ThreadCpu as u64 => Some(Self::ThreadCpu),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClockInstant {
    pub seconds: u64,
    pub nanoseconds: u32,
    pub reserved: u32,
}

/// Smallest representable increment of a native clock, not scheduling latency
/// or wall-clock accuracy. Metadata grants no timestamp or clock-write authority.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClockInfo {
    pub quantum_nanoseconds: u64,
}

/// Maximum number of generic kernel object handles carried by one IPC message.
pub const IPC_MAX_OBJECT_HANDLES: usize = 4;

/// Native object Handle labels occupy the inclusive range 1..=this capacity.
pub const PROCESS_MAX_OBJECT_HANDLES: usize = 4096;

pub const HANDLE_RIGHT_READ: u64 = 1 << 0;
pub const HANDLE_RIGHT_WRITE: u64 = 1 << 1;
pub const HANDLE_RIGHT_SEND: u64 = 1 << 2;
pub const HANDLE_RIGHT_RECEIVE: u64 = 1 << 3;
pub const HANDLE_RIGHT_WAIT: u64 = 1 << 4;
pub const HANDLE_RIGHT_SIGNAL: u64 = 1 << 5;
pub const HANDLE_RIGHT_MAP: u64 = 1 << 6;
pub const HANDLE_RIGHT_SEEK: u64 = 1 << 7;
pub const HANDLE_RIGHT_CONTROL: u64 = 1 << 8;
pub const HANDLE_RIGHT_DUPLICATE: u64 = 1 << 62;
pub const HANDLE_RIGHT_TRANSFER: u64 = 1 << 63;
pub const HANDLE_RIGHT_ALL: u64 = HANDLE_RIGHT_READ
    | HANDLE_RIGHT_WRITE
    | HANDLE_RIGHT_SEND
    | HANDLE_RIGHT_RECEIVE
    | HANDLE_RIGHT_WAIT
    | HANDLE_RIGHT_SIGNAL
    | HANDLE_RIGHT_MAP
    | HANDLE_RIGHT_SEEK
    | HANDLE_RIGHT_CONTROL
    | HANDLE_RIGHT_DUPLICATE
    | HANDLE_RIGHT_TRANSFER;

/// Native seek bases used by `HandleSeek`.
///
/// These values intentionally do not match the POSIX `SEEK_*` constants.
/// Compatibility libraries must translate their public ABI to this native
/// mechanism explicitly.
pub const HANDLE_SEEK_START: u64 = 0x4d4e_5501;
pub const HANDLE_SEEK_CURRENT: u64 = 0x4d4e_5502;
pub const HANDLE_SEEK_END: u64 = 0x4d4e_5503;

/// Return immediately when an object operation would otherwise block.
pub const HANDLE_OPTION_NONBLOCKING: u64 = 1 << 0;
pub const HANDLE_OPTIONS_ALL: u64 = HANDLE_OPTION_NONBLOCKING;

/// Require the entire supplied stream write to fit before committing bytes.
pub const STREAM_WRITE_COMPLETE: u64 = 1 << 0;
pub const STREAM_IO_TRY: u64 = 1 << 1;
pub const STREAM_READ_OPTIONS_ALL: u64 = STREAM_IO_TRY;
pub const STREAM_WRITE_OPTIONS_ALL: u64 = STREAM_WRITE_COMPLETE | STREAM_IO_TRY;

/// One process-local object handle and the rights requested for transfer.
///
/// The receiver gets a different process-local handle number. `rights` must be
/// a subset of the sender's rights and the source must include TRANSFER.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpcObjectHandle {
    pub handle: u32,
    pub reserved: u32,
    pub rights: u64,
}

/// Receiver-only proof that this delivery was generated by a native object
/// mechanism, after its authority checks. User-originated IPC cannot set it.
pub const IPC_DELIVERY_NATIVE_OBJECT: u32 = 1;

/// Receiver-only proof that the sender possessed a SEND Handle to this
/// endpoint. Legacy globally addressed messages do not carry this proof.
pub const IPC_DELIVERY_ENDPOINT_HANDLE: u32 = 2;

/// Fixed-size generic object-handle attachment buffer used by IPC syscalls.
/// `delivery_flags` must be zero on send/reply and is populated by the kernel
/// on receive. Copying these flags into a new outgoing request is not allowed.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpcObjectHandles {
    pub count: u32,
    pub delivery_flags: u32,
    pub handles: [IpcObjectHandle; IPC_MAX_OBJECT_HANDLES],
}

impl IpcObjectHandles {
    /// Ordinary user delivery, excluding native object dispatch and unknown flags.
    pub const fn is_user_delivery(&self) -> bool {
        self.delivery_flags == 0 || self.delivery_flags == IPC_DELIVERY_ENDPOINT_HANDLE
    }
}

/// `StorageControl` が受け取る、プラットフォーム固有ストレージ操作の固定長要求です。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StorageControlRequest {
    pub operation: u16,
    pub reserved0: u16,
    pub device_id: u32,
    pub arguments: [u64; 4],
}

/// `StorageControl` が返す固定長応答です。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StorageControlResponse {
    pub status: u32,
    pub device_id: u32,
    pub values: [u64; 4],
}

#[cfg(test)]
mod object_handle_tests {
    use super::*;

    #[test]
    fn object_handle_wire_layout_is_fixed() {
        assert_eq!(core::mem::size_of::<IpcObjectHandle>(), 16);
        assert_eq!(core::mem::size_of::<IpcObjectHandles>(), 72);
        assert_eq!(core::mem::align_of::<IpcObjectHandles>(), 8);
        assert_eq!(core::mem::size_of::<HandleWaitItem>(), 24);
        assert_eq!(core::mem::align_of::<HandleWaitItem>(), 8);
    }

    #[test]
    fn native_memory_access_flags_are_disjoint_and_complete() {
        let access = [
            MEMORY_ACCESS_READ,
            MEMORY_ACCESS_WRITE,
            MEMORY_ACCESS_EXECUTE,
        ];
        let mut combined = 0;
        for flag in access {
            assert_eq!(combined & flag, 0);
            combined |= flag;
        }
        assert_eq!(combined, MEMORY_ACCESS_ALL);
    }

    #[test]
    fn object_handle_rights_are_disjoint_and_complete() {
        let rights = [
            HANDLE_RIGHT_READ,
            HANDLE_RIGHT_WRITE,
            HANDLE_RIGHT_SEND,
            HANDLE_RIGHT_RECEIVE,
            HANDLE_RIGHT_WAIT,
            HANDLE_RIGHT_SIGNAL,
            HANDLE_RIGHT_MAP,
            HANDLE_RIGHT_SEEK,
            HANDLE_RIGHT_CONTROL,
            HANDLE_RIGHT_DUPLICATE,
            HANDLE_RIGHT_TRANSFER,
        ];
        let mut combined = 0;
        for right in rights {
            assert_eq!(combined & right, 0);
            combined |= right;
        }
        assert_eq!(combined, HANDLE_RIGHT_ALL);
    }

    #[test]
    fn native_handle_syscalls_do_not_overlap_filesystem_registration() {
        let numbers = [
            SyscallNumber::HandleClose as u64,
            SyscallNumber::HandleDuplicate as u64,
            SyscallNumber::LaunchHandleGet as u64,
            SyscallNumber::IpcCreateHandle as u64,
            SyscallNumber::IpcSendObjectHandles as u64,
            SyscallNumber::IpcRecvObjectHandles as u64,
            SyscallNumber::IpcCallObjectHandles as u64,
            SyscallNumber::IpcReplyObjectHandles as u64,
            SyscallNumber::HandleRead as u64,
            SyscallNumber::HandleWrite as u64,
            SyscallNumber::HandleSeek as u64,
            SyscallNumber::ProviderObjectCreate as u64,
            SyscallNumber::ProviderObjectIdentify as u64,
            SyscallNumber::LaunchValueGet as u64,
            SyscallNumber::ClockRead as u64,
            SyscallNumber::ProcessHandleOpen as u64,
            SyscallNumber::ProcessHandleStatus as u64,
            SyscallNumber::ProcessHandleWait as u64,
            SyscallNumber::ProcessHandleResume as u64,
            SyscallNumber::ProcessHandleTerminate as u64,
            SyscallNumber::HandleWaitMany as u64,
            SyscallNumber::ContextHandleSet as u64,
            SyscallNumber::StreamPairCreate as u64,
            SyscallNumber::HandleOptionsGet as u64,
            SyscallNumber::HandleOptionsSet as u64,
            SyscallNumber::WaitOnAddress as u64,
            SyscallNumber::WaitOnAddressGuarded as u64,
            SyscallNumber::WakeAddress as u64,
            SyscallNumber::ThreadUpcallInstall as u64,
            SyscallNumber::ThreadUpcallReturn as u64,
            SyscallNumber::ThreadUpcallInspect as u64,
            SyscallNumber::ThreadUpcallReturnContext as u64,
            SyscallNumber::ThreadContextRestore as u64,
            SyscallNumber::ThreadHandleCreate as u64,
            SyscallNumber::ThreadInterrupt as u64,
            SyscallNumber::ThreadHandleStatus as u64,
            SyscallNumber::ProcessHandleOpenById as u64,
            SyscallNumber::DebugWrite as u64,
            SyscallNumber::ContextHandleRemove as u64,
            SyscallNumber::ContextValueSet as u64,
            SyscallNumber::ContextValueRemove as u64,
            SyscallNumber::HandleRightsGet as u64,
            SyscallNumber::HandleSameObject as u64,
            SyscallNumber::ProviderObjectSignal as u64,
            SyscallNumber::HandleControl as u64,
            SyscallNumber::ProcessSuspendCurrent as u64,
            SyscallNumber::ProcessHandleSuspend as u64,
            SyscallNumber::AddressSpaceClone as u64,
        ];
        assert!(numbers.iter().all(|number| *number > 625));
        for (index, number) in numbers.iter().enumerate() {
            assert!(!numbers[..index].contains(number));
        }
    }
}

/// Opaque platform device messages; the selected capability scopes operations.
pub type DeviceControlRequest = StorageControlRequest;
pub type DeviceControlResponse = StorageControlResponse;

/// `arguments[0]` 番目のストレージ候補を返します。
pub const STORAGE_CONTROL_LIST_DEVICE: u16 = 0;
pub const STORAGE_CONTROL_INSPECT: u16 = 1;
pub const STORAGE_CONTROL_CREATE_PARTITION: u16 = 2;
pub const STORAGE_CONTROL_DELETE_PARTITION: u16 = 3;
pub const STORAGE_CONTROL_INSTALL_PARTITION: u16 = 4;

pub const STORAGE_STATUS_OK: u32 = 0;
pub const STORAGE_STATUS_END: u32 = 6;

pub const STORAGE_QUERY_DISK: u64 = 0;
pub const STORAGE_QUERY_PARTITION_GUIDS: u64 = 1;
pub const STORAGE_QUERY_PARTITION_RANGE: u64 = 2;

pub const APPLICATION_ID_FIELD_LEN: usize = 128;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Native execution and authenticated package identity, without POSIX credentials.
pub struct ThreadSecurityContext {
    pub process_id: u64,
    pub thread_id: u64,
    pub provenance: u8,
    pub reserved0: [u8; 7],
    pub subject_key_id: [u8; 32],
    pub package_id_len: u16,
    pub developer_id_len: u16,
    pub reserved1: u32,
    pub package_id: [u8; APPLICATION_ID_FIELD_LEN],
    pub developer_id: [u8; APPLICATION_ID_FIELD_LEN],
}

impl Default for ThreadSecurityContext {
    fn default() -> Self {
        Self {
            process_id: 0,
            thread_id: 0,
            provenance: 0,
            reserved0: [0; 7],
            subject_key_id: [0; 32],
            package_id_len: 0,
            developer_id_len: 0,
            reserved1: 0,
            package_id: [0; APPLICATION_ID_FIELD_LEN],
            developer_id: [0; APPLICATION_ID_FIELD_LEN],
        }
    }
}

#[cfg(test)]
mod syscall_layout_tests {
    use super::{StorageControlRequest, StorageControlResponse};

    #[test]
    fn storage_control_layout_is_fixed() {
        assert_eq!(core::mem::size_of::<StorageControlRequest>(), 40);
        assert_eq!(core::mem::align_of::<StorageControlRequest>(), 8);
        assert_eq!(core::mem::size_of::<StorageControlResponse>(), 40);
        assert_eq!(core::mem::align_of::<StorageControlResponse>(), 8);
    }

    #[test]
    fn boot_system_slot_syscall_number_is_stable() {
        assert_eq!(super::SyscallNumber::BootSystemSlot as u64, 618);
    }

    #[test]
    fn native_file_handle_io_abi_is_not_posix_seek_abi() {
        assert_eq!(super::SyscallNumber::HandleRead as u64, 634);
        assert_eq!(super::SyscallNumber::HandleWrite as u64, 635);
        assert_eq!(super::SyscallNumber::HandleSeek as u64, 636);
        assert_eq!(super::SyscallNumber::ProviderObjectCreate as u64, 637);
        assert_eq!(super::SyscallNumber::ProviderObjectIdentify as u64, 638);
        assert_eq!(super::SyscallNumber::ClockRead as u64, 640);
        assert_eq!(super::SyscallNumber::ProcessHandleOpen as u64, 641);
        assert_eq!(super::SyscallNumber::ProcessHandleStatus as u64, 642);
        assert_eq!(super::SyscallNumber::ProcessHandleWait as u64, 643);
        assert_eq!(super::SyscallNumber::HandleWaitMany as u64, 647);
        assert_eq!(super::SyscallNumber::ContextHandleSet as u64, 648);
        assert_eq!(super::SyscallNumber::ContextHandleRemove as u64, 661);
        assert_eq!(super::SyscallNumber::ContextValueSet as u64, 662);
        assert_eq!(super::SyscallNumber::ContextValueRemove as u64, 663);
        assert_eq!(super::SyscallNumber::HandleRightsGet as u64, 664);
        assert_eq!(super::SyscallNumber::HandleSameObject as u64, 666);
        assert_eq!(super::SyscallNumber::ProviderObjectSignal as u64, 667);
        assert_eq!(super::SyscallNumber::HandleControl as u64, 668);
        assert_eq!(super::SyscallNumber::ProcessSuspendCurrent as u64, 669);
        assert_eq!(super::SyscallNumber::ProcessHandleSuspend as u64, 670);
        assert_eq!(super::SyscallNumber::StreamPairCreate as u64, 649);
        assert_eq!(super::SyscallNumber::HandleOptionsGet as u64, 650);
        assert_eq!(super::SyscallNumber::HandleOptionsSet as u64, 651);
        assert_eq!(super::SyscallNumber::WaitOnAddress as u64, 652);
        assert_eq!(super::SyscallNumber::WakeAddress as u64, 653);
        assert_eq!(super::SyscallNumber::ThreadUpcallInstall as u64, 654);
        assert_eq!(super::SyscallNumber::ThreadUpcallReturn as u64, 655);
        assert_eq!(super::SyscallNumber::ThreadHandleCreate as u64, 656);
        assert_eq!(super::SyscallNumber::ThreadInterrupt as u64, 657);
        assert_eq!(super::SyscallNumber::ThreadHandleStatus as u64, 658);
        assert_eq!(super::SyscallNumber::ProcessHandleOpenById as u64, 659);
        assert_eq!(super::SyscallNumber::DebugWrite as u64, 660);
        assert_eq!(core::mem::size_of::<super::ThreadUpcallConfig>(), 64);
        assert_eq!(core::mem::size_of::<super::ThreadStatus>(), 24);
        assert_eq!(
            super::AddressWaitResult::from_raw(2),
            Some(super::AddressWaitResult::DeadlineReached)
        );
        assert_eq!(super::AddressWaitResult::from_raw(3), None);
        assert_eq!(core::mem::size_of::<super::StreamPair>(), 8);
        assert_eq!(super::SyscallNumber::ProcessHandleResume as u64, 645);
        assert_eq!(super::SyscallNumber::ProcessHandleTerminate as u64, 646);
        assert!(![0, 1, 2].contains(&super::HANDLE_SEEK_START));
        assert!(![0, 1, 2].contains(&super::HANDLE_SEEK_CURRENT));
        assert!(![0, 1, 2].contains(&super::HANDLE_SEEK_END));
        assert_eq!(super::HANDLE_SIGNAL_IDLE, 1 << 4);
        assert_eq!(
            super::HANDLE_SIGNAL_TERMINATED
                | super::HANDLE_SIGNAL_READABLE
                | super::HANDLE_SIGNAL_WRITABLE
                | super::HANDLE_SIGNAL_PEER_CLOSED
                | super::HANDLE_SIGNAL_IDLE,
            0x1f
        );
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DmaAllocation {
    pub handle: u64,
    pub virt_addr: u64,
    pub phys_addr: u64,
    pub len: u64,
}

/// 成功
pub const SUCCESS: u64 = 0;
/// 操作が許可されていない
pub const EPERM: u64 = (-1i64) as u64;
/// ファイルが見つからない
pub const ENOENT: u64 = (-2i64) as u64;
/// I/Oエラー
pub const EIO: u64 = (-5i64) as u64;
/// 不正なファイルディスクリプタ
pub const EBADF: u64 = (-9i64) as u64;
/// 受信/送信できない（キュー空/満杯）
pub const EAGAIN: u64 = (-11i64) as u64;
/// メモリ不足
pub const ENOMEM: u64 = (-12i64) as u64;
/// アクセス権がない
pub const EACCES: u64 = (-13i64) as u64;
/// 不正なアドレス
pub const EFAULT: u64 = (-14i64) as u64;
/// ファイルが既に存在する
pub const EEXIST: u64 = (-17i64) as u64;
/// 無効な引数
pub const EINVAL: u64 = (-22i64) as u64;
/// ディスク/ストレージに空きがない
pub const ENOSPC: u64 = (-28i64) as u64;
/// パイプが壊れている
pub const EPIPE: u64 = (-32i64) as u64;
/// 引数が範囲外
pub const ERANGE: u64 = (-34i64) as u64;
/// 未実装
pub const ENOSYS: u64 = (-38i64) as u64;
/// 値が表現可能な範囲を超える
pub const EOVERFLOW: u64 = (-75i64) as u64;
/// 操作がサポートされていない
pub const ENOTSUP: u64 = (-95i64) as u64;
