// Bounded byte history with reader-owned absolute cursors. No filesystem,
// process identity, service name, allocator, or persistence policy is involved.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorError {
    Ahead,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadResult {
    pub bytes: usize,
    pub next: u64,
    pub dropped: u64,
}

pub struct ByteRing<const N: usize> {
    data: [u8; N],
    start: usize,
    length: usize,
    head: u64,
}

impl<const N: usize> ByteRing<N> {
    pub const fn new() -> Self {
        assert!(N != 0);
        Self {
            data: [0; N],
            start: 0,
            length: 0,
            head: 0,
        }
    }

    pub fn oldest(&self) -> u64 {
        self.head
    }

    pub fn end(&self) -> u64 {
        self.head + self.length as u64
    }

    pub fn len(&self) -> usize {
        self.length
    }

    /// All cursor arithmetic is checked before changing the retained bytes.
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), CursorError> {
        let tail = self
            .end()
            .checked_add(bytes.len() as u64)
            .ok_or(CursorError::Exhausted)?;
        if bytes.len() >= N {
            self.data.copy_from_slice(&bytes[bytes.len() - N..]);
            self.start = 0;
            self.length = N;
            self.head = tail - N as u64;
            return Ok(());
        }
        let evict = bytes.len().saturating_sub(N - self.length);
        self.start = (self.start + evict) % N;
        self.length -= evict;
        self.head += evict as u64;
        let mut write = (self.start + self.length) % N;
        for &byte in bytes {
            self.data[write] = byte;
            write = (write + 1) % N;
        }
        self.length += bytes.len();
        Ok(())
    }

    /// Reading never changes the buffer or any other reader's position. The
    /// caller advances its cursor only after accepting/persisting this result.
    pub fn read(&self, cursor: u64, output: &mut [u8]) -> Result<ReadResult, CursorError> {
        if cursor > self.end() {
            return Err(CursorError::Ahead);
        }
        let begin = cursor.max(self.head);
        let offset = (begin - self.head) as usize;
        let bytes = output.len().min(self.length - offset);
        for (index, byte) in output[..bytes].iter_mut().enumerate() {
            *byte = self.data[(self.start + offset + index) % N];
        }
        Ok(ReadResult {
            bytes,
            next: begin + bytes as u64,
            dropped: self.head.saturating_sub(cursor),
        })
    }
}
