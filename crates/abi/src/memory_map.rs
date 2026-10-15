//! Native per-operation mapping ceiling. No process policy is stored here.

pub const REQUEST_LEN: usize = 64;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub address: u64,
    pub length: u64,
    pub access: u64,
    pub options: u64,
    pub backing_handle: u64,
    pub backing_offset: u64,
    /// Maximum total reserved-or-retained user virtual bytes after this map.
    /// Includes inaccessible reservations, image, stack and borrowed mappings,
    /// but counts a resident page inside a reservation only once.
    pub byte_ceiling: u64,
    pub reserved: u64,
}

impl Request {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != REQUEST_LEN {
            return None;
        }
        let word =
            |index: usize| u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap());
        let request = Self {
            address: word(0),
            length: word(1),
            access: word(2),
            options: word(3),
            backing_handle: word(4),
            backing_offset: word(5),
            byte_ceiling: word(6),
            reserved: word(7),
        };
        (request.reserved == 0).then_some(request)
    }

    pub fn encode(self) -> [u8; REQUEST_LEN] {
        let mut bytes = [0; REQUEST_LEN];
        for (index, word) in [
            self.address,
            self.length,
            self.access,
            self.options,
            self.backing_handle,
            self.backing_offset,
            self.byte_ceiling,
            self.reserved,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}
