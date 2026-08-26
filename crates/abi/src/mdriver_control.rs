pub const MDRIVER_CONTROL_VERSION: u16 = 1;

pub const MDRIVER_CONTROL_NEGOTIATE: u16 = 1;
pub const MDRIVER_CONTROL_ENUMERATE: u16 = 2;
pub const MDRIVER_CONTROL_DESCRIBE: u16 = 3;
pub const MDRIVER_CONTROL_PING: u16 = 4;
pub const MDRIVER_CONTROL_START_SESSION: u16 = 5;
pub const MDRIVER_CONTROL_OPEN_DEVICE: u16 = 6;
pub const MDRIVER_CONTROL_CLOSE_DEVICE: u16 = 7;
pub const MDRIVER_CONTROL_BLOCK_READ: u16 = 8;
pub const MDRIVER_CONTROL_BLOCK_WRITE: u16 = 9;
pub const MDRIVER_CONTROL_BLOCK_FLUSH: u16 = 10;

pub const MDRIVER_CONTROL_STATUS_OK: u32 = 0;
pub const MDRIVER_CONTROL_STATUS_UNSUPPORTED_VERSION: u32 = 1;
pub const MDRIVER_CONTROL_STATUS_INVALID_REQUEST: u32 = 2;
pub const MDRIVER_CONTROL_STATUS_UNSUPPORTED_OPERATION: u32 = 3;
pub const MDRIVER_CONTROL_STATUS_NOT_FOUND: u32 = 4;
pub const MDRIVER_CONTROL_STATUS_BAD_STATE: u32 = 5;
pub const MDRIVER_CONTROL_STATUS_END: u32 = 6;
pub const MDRIVER_CONTROL_STATUS_INTERNAL_ERROR: u32 = 7;
pub const MDRIVER_CONTROL_STATUS_IO_ERROR: u32 = 8;
pub const MDRIVER_CONTROL_STATUS_OUT_OF_RANGE: u32 = 9;

pub const MDRIVER_CONTROL_CAP_INVENTORY: u64 = 1 << 0;
pub const MDRIVER_CONTROL_CAP_DEVICE_STATUS: u64 = 1 << 1;
pub const MDRIVER_CONTROL_CAP_SESSION: u64 = 1 << 2;
pub const MDRIVER_CONTROL_CAP_PING: u64 = 1 << 3;
pub const MDRIVER_CONTROL_CAP_BLOCK_IO: u64 = 1 << 4;
pub const MDRIVER_CONTROL_CAPABILITIES: u64 = MDRIVER_CONTROL_CAP_INVENTORY
    | MDRIVER_CONTROL_CAP_DEVICE_STATUS
    | MDRIVER_CONTROL_CAP_SESSION
    | MDRIVER_CONTROL_CAP_PING
    | MDRIVER_CONTROL_CAP_BLOCK_IO;

pub const MDRIVER_DEVICE_KIND_OTHER: u64 = 0;
pub const MDRIVER_DEVICE_KIND_BLOCK: u64 = 1;
pub const MDRIVER_DEVICE_KIND_NETWORK: u64 = 2;
pub const MDRIVER_DEVICE_KIND_DISPLAY: u64 = 3;
pub const MDRIVER_DEVICE_KIND_USB: u64 = 4;
pub const MDRIVER_DEVICE_KIND_SOUND: u64 = 5;
pub const MDRIVER_DEVICE_STATE_ONLINE: u64 = 1;
pub const MDRIVER_DEVICE_FEATURE_DMA_ISOLATED: u64 = 1 << 0;
pub const MDRIVER_DEVICE_FEATURE_INTERRUPT_ACTIVE: u64 = 1 << 1;
pub const MDRIVER_DEVICE_FEATURE_PHYSICAL: u64 = 1 << 2;
pub const MDRIVER_DEVICE_FEATURE_EPHEMERAL: u64 = 1 << 3;
pub const MDRIVER_DEVICE_FEATURE_BLOCK_READ: u64 = 1 << 8;
pub const MDRIVER_DEVICE_FEATURE_BLOCK_WRITE: u64 = 1 << 9;
pub const MDRIVER_DEVICE_FEATURE_BLOCK_FLUSH: u64 = 1 << 10;

pub const MDRIVER_BLOCK_SECTOR_SIZE: u64 = 512;
pub const MDRIVER_BLOCK_MAX_TRANSFER: u64 = 4096;

pub const MDRIVER_CONTROL_PAYLOAD_SIZE: usize = 48;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MdriverControlRequest {
    pub version: u16,
    pub operation: u16,
    pub flags: u32,
    pub device_id: u32,
    pub reserved: u32,
    pub arguments: [u64; 4],
}

impl MdriverControlRequest {
    pub const fn new(operation: u16, device_id: u32, arguments: [u64; 4]) -> Self {
        Self {
            version: MDRIVER_CONTROL_VERSION,
            operation,
            flags: 0,
            device_id,
            reserved: 0,
            arguments,
        }
    }

    pub fn encode(self) -> [u8; MDRIVER_CONTROL_PAYLOAD_SIZE] {
        let mut bytes = [0; MDRIVER_CONTROL_PAYLOAD_SIZE];
        bytes[0..2].copy_from_slice(&self.version.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.operation.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.flags.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.device_id.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        for (index, value) in self.arguments.iter().enumerate() {
            let start = 16 + index * 8;
            bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            version: u16::from_le_bytes(bytes.get(0..2)?.try_into().ok()?),
            operation: u16::from_le_bytes(bytes.get(2..4)?.try_into().ok()?),
            flags: u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?),
            device_id: u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?),
            reserved: u32::from_le_bytes(bytes.get(12..16)?.try_into().ok()?),
            arguments: decode_values(bytes)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MdriverControlResponse {
    pub version: u16,
    pub operation: u16,
    pub status: u32,
    pub device_id: u32,
    pub reserved: u32,
    pub values: [u64; 4],
}

impl MdriverControlResponse {
    pub const fn new(operation: u16, status: u32, device_id: u32, values: [u64; 4]) -> Self {
        Self {
            version: MDRIVER_CONTROL_VERSION,
            operation,
            status,
            device_id,
            reserved: 0,
            values,
        }
    }

    pub fn encode(self) -> [u8; MDRIVER_CONTROL_PAYLOAD_SIZE] {
        let mut bytes = [0; MDRIVER_CONTROL_PAYLOAD_SIZE];
        bytes[0..2].copy_from_slice(&self.version.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.operation.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.status.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.device_id.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        encode_values(&mut bytes, &self.values);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            version: u16::from_le_bytes(bytes.get(0..2)?.try_into().ok()?),
            operation: u16::from_le_bytes(bytes.get(2..4)?.try_into().ok()?),
            status: u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?),
            device_id: u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?),
            reserved: u32::from_le_bytes(bytes.get(12..16)?.try_into().ok()?),
            values: decode_values(bytes)?,
        })
    }
}

fn decode_values(bytes: &[u8]) -> Option<[u64; 4]> {
    if bytes.len() != MDRIVER_CONTROL_PAYLOAD_SIZE {
        return None;
    }
    let mut values = [0; 4];
    for (index, value) in values.iter_mut().enumerate() {
        let start = 16 + index * 8;
        *value = u64::from_le_bytes(bytes.get(start..start + 8)?.try_into().ok()?);
    }
    Some(values)
}

fn encode_values(bytes: &mut [u8; MDRIVER_CONTROL_PAYLOAD_SIZE], values: &[u64; 4]) {
    for (index, value) in values.iter().enumerate() {
        let start = 16 + index * 8;
        bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_encoding_is_fixed_and_little_endian() {
        let request = MdriverControlRequest::new(0x1234, 0x89ab_cdef, [1, 2, 3, 4]);
        let bytes = request.encode();
        assert_eq!(bytes.len(), MDRIVER_CONTROL_PAYLOAD_SIZE);
        assert_eq!(&bytes[0..4], &[1, 0, 0x34, 0x12]);
        assert_eq!(&bytes[8..12], &0x89ab_cdef_u32.to_le_bytes());
        assert_eq!(MdriverControlRequest::decode(&bytes), Some(request));
    }

    #[test]
    fn malformed_payloads_are_rejected() {
        assert_eq!(MdriverControlRequest::decode(&[0; 47]), None);
        assert_eq!(MdriverControlResponse::decode(&[0; 49]), None);
    }

    #[test]
    fn response_encoding_round_trips() {
        let response = MdriverControlResponse::new(
            MDRIVER_CONTROL_DESCRIBE,
            MDRIVER_CONTROL_STATUS_OK,
            7,
            [11, 12, 13, 14],
        );
        assert_eq!(
            MdriverControlResponse::decode(&response.encode()),
            Some(response)
        );
    }
}
