//! 監査ログ
//!
//! panic の代わりに、拒否・隔離・破損検出・復旧不能な局所失敗を
//! append-only な簡易リングバッファへ記録する。

use core::fmt;
use core::fmt::Write;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::interrupt::spinlock::SpinLock;

const AUDIT_CAPACITY: usize = 256;
const AUDIT_MSG_LEN: usize = 160;
const AUDIT_FILE_CAPACITY: usize = 64 * 1024;
const AUDIT_LINE_CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventKind {
    Deny,
    Fault,
    Revoke,
    Quarantine,
    Restart,
    Policy,
    Usercopy,
    Device,
    Exec,
    Ipc,
    Memory,
}

impl AuditEventKind {
    fn as_str(self) -> &'static str {
        match self {
            AuditEventKind::Deny => "Deny",
            AuditEventKind::Fault => "Fault",
            AuditEventKind::Revoke => "Revoke",
            AuditEventKind::Quarantine => "Quarantine",
            AuditEventKind::Restart => "Restart",
            AuditEventKind::Policy => "Policy",
            AuditEventKind::Usercopy => "Usercopy",
            AuditEventKind::Device => "Device",
            AuditEventKind::Exec => "Exec",
            AuditEventKind::Ipc => "Ipc",
            AuditEventKind::Memory => "Memory",
        }
    }
}

#[derive(Clone, Copy)]
pub struct AuditRecord {
    seq: u64,
    kind: AuditEventKind,
    len: usize,
    msg: [u8; AUDIT_MSG_LEN],
}

impl AuditRecord {
    const fn empty() -> Self {
        Self {
            seq: 0,
            kind: AuditEventKind::Fault,
            len: 0,
            msg: [0; AUDIT_MSG_LEN],
        }
    }

    fn write_message(&mut self, message: &str) {
        let bytes = message.as_bytes();
        let len = bytes.len().min(AUDIT_MSG_LEN);
        self.msg[..len].copy_from_slice(&bytes[..len]);
        if len < AUDIT_MSG_LEN {
            self.msg[len..].fill(0);
        }
        self.len = len;
    }

    pub fn message(&self) -> &str {
        core::str::from_utf8(&self.msg[..self.len]).unwrap_or("<invalid-audit-utf8>")
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn kind(&self) -> AuditEventKind {
        self.kind
    }
}

impl fmt::Debug for AuditRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditRecord")
            .field("seq", &self.seq)
            .field("kind", &self.kind)
            .field("message", &self.message())
            .finish()
    }
}

struct AuditFile {
    data: crate::util::diagnostic_buffer::ByteRing<AUDIT_FILE_CAPACITY>,
}

impl AuditFile {
    const fn new() -> Self {
        Self {
            data: crate::util::diagnostic_buffer::ByteRing::new(),
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        // At cursor exhaustion retain the last valid history, never wrap a
        // reader into unrelated bytes. Console reporting remains independent.
        let _ = self.data.append(bytes);
    }

    fn append_record(&mut self, seq: u64, kind: AuditEventKind, message: &str) {
        let mut line = [0u8; AUDIT_LINE_CAPACITY];
        let mut writer = SliceWriter::new(&mut line);
        let _ = write!(
            &mut writer,
            "[AUDIT {} #{}] {}\n",
            kind.as_str(),
            seq,
            message
        );
        self.push_bytes(writer.as_bytes());
    }
}

struct SliceWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> SliceWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.pos]
    }
}

impl fmt::Write for SliceWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len().saturating_sub(self.pos);
        if bytes.len() > remaining {
            let take = remaining;
            self.buf[self.pos..self.pos + take].copy_from_slice(&bytes[..take]);
            self.pos += take;
            return Err(fmt::Error);
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }
}

static AUDIT_LOG: SpinLock<[AuditRecord; AUDIT_CAPACITY]> =
    SpinLock::new([AuditRecord::empty(); AUDIT_CAPACITY]);
static AUDIT_FILE: SpinLock<AuditFile> = SpinLock::new(AuditFile::new());
static AUDIT_SEQ: AtomicUsize = AtomicUsize::new(1);

pub fn log(kind: AuditEventKind, message: &str) {
    let seq = AUDIT_SEQ.fetch_add(1, Ordering::Relaxed) as u64;
    let idx = (seq as usize) % AUDIT_CAPACITY;
    {
        let mut log = AUDIT_LOG.lock();
        let slot = &mut log[idx];
        slot.seq = seq;
        slot.kind = kind;
        slot.write_message(message);
    }
    {
        let mut file = AUDIT_FILE.lock();
        file.append_record(seq, kind, message);
    }
    crate::warn!("[AUDIT {:?} #{seq}] {}", kind, message);
}

pub fn snapshot_into(out: &mut [AuditRecord]) -> usize {
    if out.is_empty() {
        return 0;
    }
    let next_seq = AUDIT_SEQ.load(Ordering::Acquire) as u64;
    let start_seq = next_seq.saturating_sub(AUDIT_CAPACITY as u64).max(1);
    let log = AUDIT_LOG.lock();
    let mut written = 0;
    for seq in start_seq..next_seq {
        if written >= out.len() {
            break;
        }
        let idx = (seq as usize) % AUDIT_CAPACITY;
        if log[idx].seq == seq {
            out[written] = log[idx];
            written += 1;
        }
    }
    written
}

/// Read-only diagnostic bytes with a reader-owned absolute cursor. Permission
/// checks belong to the native API which exposes this internal mechanism.
pub fn read_cursor(
    cursor: u64,
    out: &mut [u8],
) -> Result<crate::util::diagnostic_buffer::ReadResult, crate::util::diagnostic_buffer::CursorError>
{
    AUDIT_FILE.lock().data.read(cursor, out)
}
