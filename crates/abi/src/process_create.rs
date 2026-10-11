//! Native creation metadata. Keys and values have no kernel-defined policy.
//! Handles refer only to the creating process's own handle table.

pub const MAGIC: [u8; 4] = *b"MCRT";
pub const VERSION: u16 = 2;
pub const HEADER_LEN: usize = 32;
pub const HANDLE_LEN: usize = 24;
pub const VALUE_LEN: usize = 16;
pub const MAX_IDENTITY_BYTES: usize = 256;
pub const MAX_LABEL_BYTES: usize = 32;
pub const MAX_HANDLES: usize = 256;
pub const MAX_VALUES: usize = 256;
pub const MAX_REQUEST_BYTES: usize = HEADER_LEN
    + MAX_IDENTITY_BYTES
    + MAX_LABEL_BYTES
    + crate::process_image::HEADER_LEN
    + crate::process_image::MAX_RELOCATIONS * crate::process_image::RELOCATION_LEN
    + crate::process_image::MAX_STACK_BYTES
    + MAX_HANDLES * HANDLE_LEN
    + MAX_VALUES * VALUE_LEN;

/// Explicit state for either a loaded ELF or a detached address-space image.
/// The context form contains register values, never pointers to caller memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialState<'a> {
    Image(crate::process_image::StartupImage<'a>),
    Context(crate::ThreadCreateContext),
}

pub const CONTEXT_LEN: usize = 176;

fn decode_context(bytes: &[u8]) -> Result<crate::ThreadCreateContext, Error> {
    if bytes.len() != CONTEXT_LEN {
        return Err(Error::Startup);
    }
    let context = crate::ThreadCreateContext {
        entry: u64_at(bytes, 0),
        stack_pointer: u64_at(bytes, 8),
        argument: u64_at(bytes, 16),
        thread_local_base: u64_at(bytes, 24),
        flags: u64_at(bytes, 32),
        reserved: [u64_at(bytes, 40), u64_at(bytes, 48), u64_at(bytes, 56)],
        registers: crate::ThreadInitialRegisters {
            rax: u64_at(bytes, 64),
            rbx: u64_at(bytes, 72),
            rcx: u64_at(bytes, 80),
            rdx: u64_at(bytes, 88),
            rsi: u64_at(bytes, 96),
            rbp: u64_at(bytes, 104),
            r8: u64_at(bytes, 112),
            r9: u64_at(bytes, 120),
            r10: u64_at(bytes, 128),
            r11: u64_at(bytes, 136),
            r12: u64_at(bytes, 144),
            r13: u64_at(bytes, 152),
            r14: u64_at(bytes, 160),
            r15: u64_at(bytes, 168),
        },
    };
    if context.flags != 0
        || context.reserved != [0; 3]
        || context.entry == 0
        || context.stack_pointer < 16
    {
        return Err(Error::Startup);
    }
    Ok(context)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandleGrant {
    pub key: u64,
    pub source: u32,
    pub rights: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Value {
    pub key: u64,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Length,
    Identity,
    Label,
    Startup,
    Handle,
    DuplicateKey,
    BufferTooSmall,
}

#[derive(Clone, Copy)]
pub struct Request<'a> {
    pub identity: &'a str,
    /// User-supplied diagnostic label, independent of authorization identity.
    pub label: &'a str,
    pub startup: InitialState<'a>,
    handles: &'a [u8],
    values: &'a [u8],
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

impl Request<'_> {
    pub fn handles(&self) -> impl Iterator<Item = HandleGrant> + '_ {
        self.handles
            .chunks_exact(HANDLE_LEN)
            .map(|record| HandleGrant {
                key: u64_at(record, 0),
                source: u32_at(record, 8),
                rights: u64_at(record, 16),
            })
    }

    pub fn values(&self) -> impl Iterator<Item = Value> + '_ {
        self.values.chunks_exact(VALUE_LEN).map(|record| Value {
            key: u64_at(record, 0),
            value: u64_at(record, 8),
        })
    }
}

pub fn decode(bytes: &[u8]) -> Result<Request<'_>, Error> {
    if bytes.len() < HEADER_LEN || bytes.len() > MAX_REQUEST_BYTES {
        return Err(Error::Length);
    }
    if bytes[..4] != MAGIC
        || bytes[4..6] != VERSION.to_le_bytes()
        || bytes[6..8] != (HEADER_LEN as u16).to_le_bytes()
        || u32_at(bytes, 28) > 1
    {
        return Err(Error::Header);
    }
    let identity_len = u32_at(bytes, 8) as usize;
    let startup_len = u32_at(bytes, 12) as usize;
    let handles = u32_at(bytes, 16) as usize;
    let values = u32_at(bytes, 20) as usize;
    let label_len = u32_at(bytes, 24) as usize;
    if identity_len == 0
        || identity_len > MAX_IDENTITY_BYTES
        || handles > MAX_HANDLES
        || values > MAX_VALUES
        || label_len == 0
        || label_len > MAX_LABEL_BYTES
    {
        return Err(Error::Length);
    }
    let identity_end = HEADER_LEN + identity_len;
    let label_end = identity_end.checked_add(label_len).ok_or(Error::Length)?;
    let startup_end = label_end.checked_add(startup_len).ok_or(Error::Length)?;
    let handles_end = startup_end
        .checked_add(handles * HANDLE_LEN)
        .ok_or(Error::Length)?;
    let end = handles_end
        .checked_add(values * VALUE_LEN)
        .ok_or(Error::Length)?;
    if end != bytes.len() {
        return Err(Error::Length);
    }
    let identity =
        core::str::from_utf8(&bytes[HEADER_LEN..identity_end]).map_err(|_| Error::Identity)?;
    if identity.as_bytes().contains(&0) {
        return Err(Error::Identity);
    }
    let label = core::str::from_utf8(&bytes[identity_end..label_end]).map_err(|_| Error::Label)?;
    if label.as_bytes().contains(&0) {
        return Err(Error::Label);
    }
    let startup = match u32_at(bytes, 28) {
        0 => InitialState::Image(
            crate::process_image::decode(&bytes[label_end..startup_end])
                .map_err(|_| Error::Startup)?,
        ),
        1 => InitialState::Context(decode_context(&bytes[label_end..startup_end])?),
        _ => return Err(Error::Header),
    };
    let request = Request {
        identity,
        label,
        startup,
        handles: &bytes[startup_end..handles_end],
        values: &bytes[handles_end..],
    };
    for (index, grant) in request.handles().enumerate() {
        if grant.source == 0 || u32_at(request.handles, index * HANDLE_LEN + 12) != 0 {
            return Err(Error::Handle);
        }
        if request
            .handles()
            .take(index)
            .any(|previous| previous.key == grant.key)
        {
            return Err(Error::DuplicateKey);
        }
    }
    for (index, value) in request.values().enumerate() {
        if request
            .values()
            .take(index)
            .any(|previous| previous.key == value.key)
        {
            return Err(Error::DuplicateKey);
        }
    }
    Ok(request)
}

pub fn encode(
    identity: &str,
    label: &str,
    startup: &[u8],
    handles: &[HandleGrant],
    values: &[Value],
    output: &mut [u8],
) -> Result<usize, Error> {
    encode_state(identity, label, startup, 0, handles, values, output)
}

/// Serializes a register context for creation from an address-space image.
/// Flags and reserved fields must be zero; privileged CPU state is not supplied.
pub fn encode_context(
    identity: &str,
    label: &str,
    context: &crate::ThreadCreateContext,
    handles: &[HandleGrant],
    values: &[Value],
    output: &mut [u8],
) -> Result<usize, Error> {
    let r = context.registers;
    let words = [
        context.entry,
        context.stack_pointer,
        context.argument,
        context.thread_local_base,
        context.flags,
        context.reserved[0],
        context.reserved[1],
        context.reserved[2],
        r.rax,
        r.rbx,
        r.rcx,
        r.rdx,
        r.rsi,
        r.rbp,
        r.r8,
        r.r9,
        r.r10,
        r.r11,
        r.r12,
        r.r13,
        r.r14,
        r.r15,
    ];
    let mut bytes = [0; CONTEXT_LEN];
    for (word, record) in words.iter().zip(bytes.chunks_exact_mut(8)) {
        record.copy_from_slice(&word.to_le_bytes());
    }
    encode_state(identity, label, &bytes, 1, handles, values, output)
}

fn encode_state(
    identity: &str,
    label: &str,
    startup: &[u8],
    kind: u32,
    handles: &[HandleGrant],
    values: &[Value],
    output: &mut [u8],
) -> Result<usize, Error> {
    if identity.is_empty()
        || identity.len() > MAX_IDENTITY_BYTES
        || label.is_empty()
        || label.len() > MAX_LABEL_BYTES
        || handles.len() > MAX_HANDLES
        || values.len() > MAX_VALUES
        || startup.len() > MAX_REQUEST_BYTES
    {
        return Err(Error::Length);
    }
    let length = HEADER_LEN
        + identity.len()
        + label.len()
        + startup.len()
        + handles.len() * HANDLE_LEN
        + values.len() * VALUE_LEN;
    let output = output.get_mut(..length).ok_or(Error::BufferTooSmall)?;
    output.fill(0);
    output[..4].copy_from_slice(&MAGIC);
    output[4..6].copy_from_slice(&VERSION.to_le_bytes());
    output[6..8].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
    output[28..32].copy_from_slice(&kind.to_le_bytes());
    for (offset, value) in [
        (8, identity.len()),
        (12, startup.len()),
        (16, handles.len()),
        (20, values.len()),
        (24, label.len()),
    ] {
        output[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
    }
    let mut cursor = HEADER_LEN;
    output[cursor..cursor + identity.len()].copy_from_slice(identity.as_bytes());
    cursor += identity.len();
    output[cursor..cursor + label.len()].copy_from_slice(label.as_bytes());
    cursor += label.len();
    output[cursor..cursor + startup.len()].copy_from_slice(startup);
    cursor += startup.len();
    for grant in handles {
        output[cursor..cursor + 8].copy_from_slice(&grant.key.to_le_bytes());
        output[cursor + 8..cursor + 12].copy_from_slice(&grant.source.to_le_bytes());
        output[cursor + 16..cursor + 24].copy_from_slice(&grant.rights.to_le_bytes());
        cursor += HANDLE_LEN;
    }
    for value in values {
        output[cursor..cursor + 8].copy_from_slice(&value.key.to_le_bytes());
        output[cursor + 8..cursor + 16].copy_from_slice(&value.value.to_le_bytes());
        cursor += VALUE_LEN;
    }
    decode(output)?;
    Ok(length)
}
