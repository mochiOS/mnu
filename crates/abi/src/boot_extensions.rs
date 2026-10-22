//! A complete bounded index of boot-selected code, with no filesystem names.
//! All offsets are relative to this index and refer to adjacent, disjoint
//! payloads. Validate the entire index before executing any selected module.
pub const MAGIC: [u8; 8] = *b"MNUXMOD\0";
pub const VERSION: u32 = 1;
pub const HEADER_LEN: usize = 24;
pub const ENTRY_LEN: usize = 24;
pub const MAX_ENTRIES: usize = 64;
pub const MAX_BYTES: usize = 64 * 1024 * 1024;
pub const ADAPTER_BLOCK: u32 = 1;
pub const REQUIRED: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidHeader,
    InvalidRange,
    UnsupportedAdapter,
    LimitExceeded,
}

#[derive(Clone, Copy, Debug)]
pub struct Modules<'a> {
    bytes: &'a [u8],
    count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub adapter: u32,
    pub required: bool,
    pub bytes: &'a [u8],
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

pub fn decode(bytes: &[u8]) -> Result<Modules<'_>, Error> {
    if bytes.is_empty() {
        return Ok(Modules { bytes, count: 0 });
    }
    if bytes.len() > MAX_BYTES {
        return Err(Error::LimitExceeded);
    }
    if bytes.len() < HEADER_LEN
        || bytes[..8] != MAGIC
        || u32_at(bytes, 8) != VERSION
        || u32_at(bytes, 12) != ENTRY_LEN as u32
    {
        return Err(Error::InvalidHeader);
    }
    let count = usize::try_from(u64_at(bytes, 16)).map_err(|_| Error::LimitExceeded)?;
    if count > MAX_ENTRIES {
        return Err(Error::LimitExceeded);
    }
    let mut cursor = HEADER_LEN + count * ENTRY_LEN;
    if cursor > bytes.len() {
        return Err(Error::InvalidRange);
    }
    for index in 0..count {
        let at = HEADER_LEN + index * ENTRY_LEN;
        let offset = usize::try_from(u64_at(bytes, at)).map_err(|_| Error::InvalidRange)?;
        let length = usize::try_from(u64_at(bytes, at + 8)).map_err(|_| Error::InvalidRange)?;
        if u32_at(bytes, at + 16) != ADAPTER_BLOCK {
            return Err(Error::UnsupportedAdapter);
        }
        if u32_at(bytes, at + 20) & !REQUIRED != 0 {
            return Err(Error::InvalidHeader);
        }
        if offset != cursor || length == 0 {
            return Err(Error::InvalidRange);
        }
        cursor = cursor
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(Error::InvalidRange)?;
    }
    if cursor != bytes.len() {
        return Err(Error::InvalidRange);
    }
    Ok(Modules { bytes, count })
}

impl<'a> Modules<'a> {
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn get(&self, index: usize) -> Option<Entry<'a>> {
        if index >= self.count {
            return None;
        }
        let at = HEADER_LEN + index * ENTRY_LEN;
        // The complete immutable table was validated before construction.
        let offset = u64_at(self.bytes, at) as usize;
        let length = u64_at(self.bytes, at + 8) as usize;
        Some(Entry {
            adapter: u32_at(self.bytes, at + 16),
            required: u32_at(self.bytes, at + 20) & REQUIRED != 0,
            bytes: &self.bytes[offset..offset + length],
        })
    }
}
