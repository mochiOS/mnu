//! Wire protocol used by generic user-space-backed kernel objects.
//!
//! This protocol deliberately describes object operations, not filesystem or
//! POSIX concepts. Providers own the meaning and lifetime of `object_id`.

pub const MAGIC: u32 = u32::from_le_bytes(*b"MNUP");
pub const VERSION: u16 = 1;

pub const OP_READ: u16 = 1;
pub const OP_WRITE: u16 = 2;
pub const OP_SEEK: u16 = 3;
pub const OP_RELEASE: u16 = 4;
pub const OP_CONTROL: u16 = 5;
pub const OP_READ_AT: u16 = 6;
pub const OP_WRITE_AT: u16 = 7;
pub const OP_SYNC: u16 = 8;
pub const OP_MEMORY_OBJECT: u16 = 9;
/// Sequential read with an atomically captured starting byte position.
/// Successful payloads contain a little-endian u64 position, then `value` bytes.
pub const OP_READ_WITH_POSITION: u16 = 10;
/// Sequential read into one IPC-attached MemoryObject. `basis` is the byte
/// offset within the object, not a pointer or handle number. The receiver must
/// require READ | WRITE | MAP, validate the mapping bounds, and close the attachment.
/// Success returns the byte count in `value` and an inline u64 starting position.
pub const OP_READ_SHARED: u16 = 11;

pub const REQUEST_HEADER_LEN: usize = 48;
pub const RESPONSE_HEADER_LEN: usize = 40;
pub const MAX_DATA_LEN: usize = 4096;
pub const READ_POSITION_LEN: usize = 8;
pub const MAX_POSITIONED_READ_LEN: usize = MAX_DATA_LEN - READ_POSITION_LEN;
pub const MAX_SHARED_READ_LEN: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestHeader {
    pub opcode: u16,
    pub object_id: u64,
    pub argument: i64,
    pub basis: u64,
    pub length: u32,
    pub data_length: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseHeader {
    pub opcode: u16,
    pub status: i64,
    pub object_id: u64,
    pub value: u64,
    pub data_length: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    InvalidMagic,
    InvalidVersion,
    InvalidOpcode,
    InvalidReserved,
    InvalidLength,
    InvalidFields,
}

impl RequestHeader {
    pub fn encode(self, data: &[u8], output: &mut [u8]) -> Result<usize, DecodeError> {
        if !valid_opcode(self.opcode)
            || data.len() > MAX_DATA_LEN
            || self.data_length as usize != data.len()
            || !valid_request_fields(self)
        {
            return Err(DecodeError::InvalidFields);
        }
        let total = REQUEST_HEADER_LEN + data.len();
        if output.len() < total {
            return Err(DecodeError::TooShort);
        }
        output[..total].fill(0);
        put_u32(output, 0, MAGIC);
        put_u16(output, 4, VERSION);
        put_u16(output, 6, self.opcode);
        put_u64(output, 8, self.object_id);
        put_u64(output, 16, self.argument as u64);
        put_u64(output, 24, self.basis);
        put_u32(output, 32, self.length);
        put_u32(output, 36, self.data_length);
        output[REQUEST_HEADER_LEN..total].copy_from_slice(data);
        Ok(total)
    }

    pub fn decode(input: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        if input.len() < REQUEST_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        validate_common(input)?;
        if input[40..48].iter().any(|byte| *byte != 0) {
            return Err(DecodeError::InvalidReserved);
        }
        let header = Self {
            opcode: get_u16(input, 6),
            object_id: get_u64(input, 8),
            argument: get_u64(input, 16) as i64,
            basis: get_u64(input, 24),
            length: get_u32(input, 32),
            data_length: get_u32(input, 36),
        };
        let data_len = header.data_length as usize;
        if data_len > MAX_DATA_LEN || input.len() != REQUEST_HEADER_LEN + data_len {
            return Err(DecodeError::InvalidLength);
        }
        if !valid_request_fields(header) {
            return Err(DecodeError::InvalidFields);
        }
        Ok((header, &input[REQUEST_HEADER_LEN..]))
    }
}

impl ResponseHeader {
    pub fn encode(self, data: &[u8], output: &mut [u8]) -> Result<usize, DecodeError> {
        if !valid_opcode(self.opcode)
            || !valid_status(self.status)
            || data.len() > MAX_DATA_LEN
            || self.data_length as usize != data.len()
            || !valid_response_fields(self)
        {
            return Err(DecodeError::InvalidFields);
        }
        let total = RESPONSE_HEADER_LEN + data.len();
        if output.len() < total {
            return Err(DecodeError::TooShort);
        }
        output[..total].fill(0);
        put_u32(output, 0, MAGIC);
        put_u16(output, 4, VERSION);
        put_u16(output, 6, self.opcode);
        put_u64(output, 8, self.status as u64);
        put_u64(output, 16, self.object_id);
        put_u64(output, 24, self.value);
        put_u32(output, 32, self.data_length);
        output[RESPONSE_HEADER_LEN..total].copy_from_slice(data);
        Ok(total)
    }

    pub fn decode(input: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        if input.len() < RESPONSE_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        validate_common(input)?;
        if input[36..40].iter().any(|byte| *byte != 0) {
            return Err(DecodeError::InvalidReserved);
        }
        let header = Self {
            opcode: get_u16(input, 6),
            status: get_u64(input, 8) as i64,
            object_id: get_u64(input, 16),
            value: get_u64(input, 24),
            data_length: get_u32(input, 32),
        };
        let data_len = header.data_length as usize;
        if !valid_status(header.status)
            || data_len > MAX_DATA_LEN
            || input.len() != RESPONSE_HEADER_LEN + data_len
        {
            return Err(DecodeError::InvalidLength);
        }
        if !valid_response_fields(header) {
            return Err(DecodeError::InvalidFields);
        }
        Ok((header, &input[RESPONSE_HEADER_LEN..]))
    }
}

const fn valid_opcode(opcode: u16) -> bool {
    matches!(
        opcode,
        OP_READ
            | OP_WRITE
            | OP_SEEK
            | OP_RELEASE
            | OP_CONTROL
            | OP_READ_AT
            | OP_WRITE_AT
            | OP_SYNC
            | OP_MEMORY_OBJECT
            | OP_READ_WITH_POSITION
            | OP_READ_SHARED
    )
}

const fn valid_request_fields(header: RequestHeader) -> bool {
    match header.opcode {
        OP_READ => {
            header.argument == 0
                && header.basis == 0
                && header.data_length == 0
                && header.length as usize <= MAX_DATA_LEN
        }
        OP_READ_WITH_POSITION => {
            header.argument == 0
                && header.basis == 0
                && header.data_length == 0
                && header.length as usize <= MAX_POSITIONED_READ_LEN
        }
        OP_READ_SHARED => {
            header.argument == 0
                && header.data_length == 0
                && header.length != 0
                && header.length as usize <= MAX_SHARED_READ_LEN
                && header.basis.checked_add(header.length as u64).is_some()
        }
        OP_WRITE => {
            header.argument == 0
                && header.basis == 0
                && header.length == header.data_length
                && header.length as usize <= MAX_DATA_LEN
        }
        OP_SEEK => {
            header.length == 0
                && header.data_length == 0
                && matches!(
                    header.basis,
                    crate::HANDLE_SEEK_START | crate::HANDLE_SEEK_CURRENT | crate::HANDLE_SEEK_END
                )
        }
        OP_RELEASE => {
            header.argument == 0
                && header.basis == 0
                && header.length == 0
                && header.data_length == 0
        }
        OP_CONTROL => {
            header.argument == 0
                && header.length as usize <= MAX_DATA_LEN
                && header.data_length as usize <= MAX_DATA_LEN
        }
        OP_READ_AT => {
            header.argument == 0
                && header.data_length == 0
                && header.length as usize <= MAX_DATA_LEN
        }
        OP_WRITE_AT => {
            header.argument == 0
                && header.length == header.data_length
                && header.length as usize <= MAX_DATA_LEN
        }
        OP_SYNC => {
            header.argument == 0
                && header.basis == 0
                && header.length == 0
                && header.data_length == 0
        }
        OP_MEMORY_OBJECT => {
            header.argument == 0
                && header.basis == 0
                && header.length == 0
                && header.data_length == 0
        }
        _ => false,
    }
}

const fn valid_status(status: i64) -> bool {
    status == 0 || (status >= -4095 && status <= -1)
}

const fn valid_response_fields(header: ResponseHeader) -> bool {
    if header.status != 0 {
        return header.value == 0 && header.data_length == 0;
    }
    match header.opcode {
        OP_READ | OP_READ_AT | OP_CONTROL => header.value == header.data_length as u64,
        OP_READ_WITH_POSITION => {
            header.data_length as usize >= READ_POSITION_LEN
                && header.value == (header.data_length as usize - READ_POSITION_LEN) as u64
        }
        OP_READ_SHARED => {
            header.data_length as usize == READ_POSITION_LEN
                && header.value <= MAX_SHARED_READ_LEN as u64
        }
        // Positioned providers may return the starting byte offset alongside
        // a sequential write result, captured by the same operation.
        OP_WRITE => header.data_length == 0 || header.data_length == 8,
        OP_WRITE_AT | OP_SEEK | OP_RELEASE | OP_SYNC => header.data_length == 0,
        OP_MEMORY_OBJECT => header.value != 0 && header.data_length == 0,
        _ => false,
    }
}

fn validate_common(input: &[u8]) -> Result<(), DecodeError> {
    if get_u32(input, 0) != MAGIC {
        return Err(DecodeError::InvalidMagic);
    }
    if get_u16(input, 4) != VERSION {
        return Err(DecodeError::InvalidVersion);
    }
    if !valid_opcode(get_u16(input, 6)) {
        return Err(DecodeError::InvalidOpcode);
    }
    Ok(())
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([input[offset], input[offset + 1]])
}

fn get_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap())
}

fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_is_strict() {
        let header = RequestHeader {
            opcode: OP_WRITE,
            object_id: 7,
            argument: 0,
            basis: 0,
            length: 3,
            data_length: 3,
        };
        let mut bytes = [0u8; REQUEST_HEADER_LEN + 3];
        let length = header.encode(b"abc", &mut bytes).unwrap();
        assert_eq!(
            RequestHeader::decode(&bytes[..length]),
            Ok((header, &b"abc"[..]))
        );
        bytes[47] = 1;
        assert_eq!(
            RequestHeader::decode(&bytes),
            Err(DecodeError::InvalidReserved)
        );
    }

    #[test]
    fn successful_read_reply_binds_length_to_payload() {
        let header = ResponseHeader {
            opcode: OP_READ,
            status: 0,
            object_id: 9,
            value: 2,
            data_length: 2,
        };
        let mut bytes = [0u8; RESPONSE_HEADER_LEN + 2];
        let length = header.encode(b"ok", &mut bytes).unwrap();
        assert_eq!(
            ResponseHeader::decode(&bytes[..length]),
            Ok((header, &b"ok"[..]))
        );
        bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            ResponseHeader::decode(&bytes),
            Err(DecodeError::InvalidLength)
        );
    }

    #[test]
    fn control_round_trip_keeps_code_and_bounded_payloads() {
        let header = RequestHeader {
            opcode: OP_CONTROL,
            object_id: 11,
            argument: 0,
            basis: 0xfeed_beef,
            length: 8,
            data_length: 3,
        };
        let mut request = [0u8; REQUEST_HEADER_LEN + 3];
        let request_len = header.encode(b"set", &mut request).unwrap();
        assert_eq!(
            RequestHeader::decode(&request[..request_len]),
            Ok((header, &b"set"[..]))
        );

        let response = ResponseHeader {
            opcode: OP_CONTROL,
            status: 0,
            object_id: 11,
            value: 3,
            data_length: 3,
        };
        let mut reply = [0u8; RESPONSE_HEADER_LEN + 3];
        let reply_len = response.encode(b"get", &mut reply).unwrap();
        assert_eq!(
            ResponseHeader::decode(&reply[..reply_len]),
            Ok((response, &b"get"[..]))
        );
    }
}
