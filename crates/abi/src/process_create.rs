//! Native creation metadata. Keys and values have no kernel-defined policy.
//! Handles refer only to the creating process's own handle table.

pub const MAGIC: [u8; 4] = *b"MCRT";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 32;
pub const HANDLE_LEN: usize = 24;
pub const VALUE_LEN: usize = 16;
pub const MAX_IDENTITY_BYTES: usize = 256;
pub const MAX_HANDLES: usize = 256;
pub const MAX_VALUES: usize = 256;
pub const MAX_REQUEST_BYTES: usize = HEADER_LEN
    + MAX_IDENTITY_BYTES
    + crate::process_image::HEADER_LEN
    + crate::process_image::MAX_RELOCATIONS * crate::process_image::RELOCATION_LEN
    + crate::process_image::MAX_STACK_BYTES
    + MAX_HANDLES * HANDLE_LEN
    + MAX_VALUES * VALUE_LEN;

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
    Startup,
    Handle,
    DuplicateKey,
    BufferTooSmall,
}

#[derive(Clone, Copy)]
pub struct Request<'a> {
    pub identity: &'a str,
    pub startup: crate::process_image::StartupImage<'a>,
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
        || bytes[24..HEADER_LEN].iter().any(|byte| *byte != 0)
    {
        return Err(Error::Header);
    }
    let identity_len = u32_at(bytes, 8) as usize;
    let startup_len = u32_at(bytes, 12) as usize;
    let handles = u32_at(bytes, 16) as usize;
    let values = u32_at(bytes, 20) as usize;
    if identity_len == 0
        || identity_len > MAX_IDENTITY_BYTES
        || handles > MAX_HANDLES
        || values > MAX_VALUES
    {
        return Err(Error::Length);
    }
    let identity_end = HEADER_LEN + identity_len;
    let startup_end = identity_end.checked_add(startup_len).ok_or(Error::Length)?;
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
    let startup = crate::process_image::decode(&bytes[identity_end..startup_end])
        .map_err(|_| Error::Startup)?;
    let request = Request {
        identity,
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
    startup: &[u8],
    handles: &[HandleGrant],
    values: &[Value],
    output: &mut [u8],
) -> Result<usize, Error> {
    if identity.is_empty()
        || identity.len() > MAX_IDENTITY_BYTES
        || handles.len() > MAX_HANDLES
        || values.len() > MAX_VALUES
        || startup.len() > MAX_REQUEST_BYTES
    {
        return Err(Error::Length);
    }
    let length = HEADER_LEN
        + identity.len()
        + startup.len()
        + handles.len() * HANDLE_LEN
        + values.len() * VALUE_LEN;
    let output = output.get_mut(..length).ok_or(Error::BufferTooSmall)?;
    output.fill(0);
    output[..4].copy_from_slice(&MAGIC);
    output[4..6].copy_from_slice(&VERSION.to_le_bytes());
    output[6..8].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
    for (offset, value) in [
        (8, identity.len()),
        (12, startup.len()),
        (16, handles.len()),
        (20, values.len()),
    ] {
        output[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
    }
    let mut cursor = HEADER_LEN;
    output[cursor..cursor + identity.len()].copy_from_slice(identity.as_bytes());
    cursor += identity.len();
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
