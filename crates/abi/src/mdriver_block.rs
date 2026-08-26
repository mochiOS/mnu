pub const MDRIVER_BLOCK_VERSION: u16 = 1;

pub const MDRIVER_BLOCK_READ: u16 = 1;
pub const MDRIVER_BLOCK_WRITE: u16 = 2;
pub const MDRIVER_BLOCK_FLUSH: u16 = 3;

pub const MDRIVER_BLOCK_STATUS_OK: u32 = 0;
pub const MDRIVER_BLOCK_STATUS_INVALID_REQUEST: u32 = 1;
pub const MDRIVER_BLOCK_STATUS_IO_ERROR: u32 = 2;
pub const MDRIVER_BLOCK_STATUS_OUT_OF_RANGE: u32 = 3;
pub const MDRIVER_BLOCK_STATUS_BAD_STATE: u32 = 4;
pub const MDRIVER_BLOCK_STATUS_READ_ONLY: u32 = 5;

pub const MDRIVER_BLOCK_PAYLOAD_SIZE: usize = 48;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MdriverBlockRequest {
    pub version: u16,
    pub operation: u16,
    pub flags: u32,
    pub device_id: u32,
    pub buffer_id: u32,
    pub sector: u64,
    pub length: u32,
    pub buffer_offset: u32,
    pub reserved: [u64; 2],
}

impl MdriverBlockRequest {
    pub const fn new(
        operation: u16,
        device_id: u32,
        buffer_id: u32,
        sector: u64,
        length: u32,
        buffer_offset: u32,
    ) -> Self {
        Self {
            version: MDRIVER_BLOCK_VERSION,
            operation,
            flags: 0,
            device_id,
            buffer_id,
            sector,
            length,
            buffer_offset,
            reserved: [0; 2],
        }
    }

    pub fn encode(self) -> [u8; MDRIVER_BLOCK_PAYLOAD_SIZE] {
        let mut bytes = [0; MDRIVER_BLOCK_PAYLOAD_SIZE];
        bytes[0..2].copy_from_slice(&self.version.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.operation.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.flags.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.device_id.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.buffer_id.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.sector.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.length.to_le_bytes());
        bytes[28..32].copy_from_slice(&self.buffer_offset.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.reserved[0].to_le_bytes());
        bytes[40..48].copy_from_slice(&self.reserved[1].to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != MDRIVER_BLOCK_PAYLOAD_SIZE {
            return None;
        }
        Some(Self {
            version: read_u16(bytes, 0)?,
            operation: read_u16(bytes, 2)?,
            flags: read_u32(bytes, 4)?,
            device_id: read_u32(bytes, 8)?,
            buffer_id: read_u32(bytes, 12)?,
            sector: read_u64(bytes, 16)?,
            length: read_u32(bytes, 24)?,
            buffer_offset: read_u32(bytes, 28)?,
            reserved: [read_u64(bytes, 32)?, read_u64(bytes, 40)?],
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MdriverBlockResponse {
    pub version: u16,
    pub operation: u16,
    pub status: u32,
    pub device_id: u32,
    pub buffer_id: u32,
    pub transferred: u32,
    pub reserved0: u32,
    pub sector: u64,
    pub reserved: [u64; 2],
}

impl MdriverBlockResponse {
    pub const fn new(request: MdriverBlockRequest, status: u32, transferred: u32) -> Self {
        Self {
            version: MDRIVER_BLOCK_VERSION,
            operation: request.operation,
            status,
            device_id: request.device_id,
            buffer_id: request.buffer_id,
            transferred,
            reserved0: 0,
            sector: request.sector,
            reserved: [0; 2],
        }
    }

    pub fn encode(self) -> [u8; MDRIVER_BLOCK_PAYLOAD_SIZE] {
        let mut bytes = [0; MDRIVER_BLOCK_PAYLOAD_SIZE];
        bytes[0..2].copy_from_slice(&self.version.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.operation.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.status.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.device_id.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.buffer_id.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.transferred.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.reserved0.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.sector.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.reserved[0].to_le_bytes());
        bytes[40..48].copy_from_slice(&self.reserved[1].to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != MDRIVER_BLOCK_PAYLOAD_SIZE {
            return None;
        }
        Some(Self {
            version: read_u16(bytes, 0)?,
            operation: read_u16(bytes, 2)?,
            status: read_u32(bytes, 4)?,
            device_id: read_u32(bytes, 8)?,
            buffer_id: read_u32(bytes, 12)?,
            transferred: read_u32(bytes, 16)?,
            reserved0: read_u32(bytes, 20)?,
            sector: read_u64(bytes, 24)?,
            reserved: [read_u64(bytes, 32)?, read_u64(bytes, 40)?],
        })
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_encoding_round_trips() {
        let request = MdriverBlockRequest::new(MDRIVER_BLOCK_WRITE, 7, 3, 0x1234, 4096, 0);
        assert_eq!(
            MdriverBlockRequest::decode(&request.encode()),
            Some(request)
        );
    }

    #[test]
    fn response_encoding_round_trips() {
        let request = MdriverBlockRequest::new(MDRIVER_BLOCK_READ, 2, 1, 8, 512, 0);
        let response = MdriverBlockResponse::new(request, MDRIVER_BLOCK_STATUS_OK, 512);
        assert_eq!(
            MdriverBlockResponse::decode(&response.encode()),
            Some(response)
        );
    }

    #[test]
    fn malformed_payloads_are_rejected() {
        assert_eq!(MdriverBlockRequest::decode(&[0; 47]), None);
        assert_eq!(MdriverBlockResponse::decode(&[0; 49]), None);
    }
}
