use core::ptr::{addr_of, addr_of_mut, read_volatile, write, write_volatile};
use core::sync::atomic::{AtomicU32, Ordering};

pub const SHARED_RING_MAGIC: u64 = u64::from_le_bytes(*b"MNURING\0");
pub const SHARED_RING_VERSION: u32 = 1;
pub const SHARED_RING_SLOT_COUNT: usize = 31;
pub const SHARED_RING_PAYLOAD_SIZE: usize = 48;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedRingError {
    InvalidHeader,
    PayloadTooLarge,
    Full,
    Empty,
    CorruptEntry,
}

#[repr(C)]
pub struct SharedRingHeader {
    magic: u64,
    version: u32,
    slot_count: u32,
    request_producer: AtomicU32,
    request_consumer: AtomicU32,
    response_producer: AtomicU32,
    response_consumer: AtomicU32,
    generation: u64,
    reserved: [u64; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedRingMessage {
    pub kind: u16,
    pub flags: u16,
    pub len: u32,
    pub request_id: u64,
    pub payload: [u8; SHARED_RING_PAYLOAD_SIZE],
}

impl SharedRingMessage {
    pub fn new(
        kind: u16,
        flags: u16,
        request_id: u64,
        payload: &[u8],
    ) -> Result<Self, SharedRingError> {
        if payload.len() > SHARED_RING_PAYLOAD_SIZE {
            return Err(SharedRingError::PayloadTooLarge);
        }
        let mut message = Self {
            kind,
            flags,
            len: payload.len() as u32,
            request_id,
            payload: [0; SHARED_RING_PAYLOAD_SIZE],
        };
        message.payload[..payload.len()].copy_from_slice(payload);
        Ok(message)
    }

    pub fn data(&self) -> Result<&[u8], SharedRingError> {
        let len = self.len as usize;
        self.payload.get(..len).ok_or(SharedRingError::CorruptEntry)
    }
}

#[repr(C, align(64))]
pub struct SharedRingPage {
    header: SharedRingHeader,
    requests: [SharedRingMessage; SHARED_RING_SLOT_COUNT],
    responses: [SharedRingMessage; SHARED_RING_SLOT_COUNT],
    reserved: [u8; 64],
}

const EMPTY_MESSAGE: SharedRingMessage = SharedRingMessage {
    kind: 0,
    flags: 0,
    len: 0,
    request_id: 0,
    payload: [0; SHARED_RING_PAYLOAD_SIZE],
};

/// Initializes one exclusively owned, page-aligned ring page.
///
/// # Safety
/// `ring` must point to a writable 4096-byte page that no other Domain can use
/// until this function returns.
pub unsafe fn initialize(ring: *mut SharedRingPage, generation: u64) {
    unsafe {
        write(
            ring,
            SharedRingPage {
                header: SharedRingHeader {
                    magic: SHARED_RING_MAGIC,
                    version: SHARED_RING_VERSION,
                    slot_count: SHARED_RING_SLOT_COUNT as u32,
                    request_producer: AtomicU32::new(0),
                    request_consumer: AtomicU32::new(0),
                    response_producer: AtomicU32::new(0),
                    response_consumer: AtomicU32::new(0),
                    generation,
                    reserved: [0; 3],
                },
                requests: [EMPTY_MESSAGE; SHARED_RING_SLOT_COUNT],
                responses: [EMPTY_MESSAGE; SHARED_RING_SLOT_COUNT],
                reserved: [0; 64],
            },
        )
    };
}

/// Checks the immutable header fields before either endpoint uses the ring.
///
/// # Safety
/// `ring` must point to a mapped `SharedRingPage` for the duration of this call.
pub unsafe fn validate(ring: *const SharedRingPage) -> Result<u64, SharedRingError> {
    let header = unsafe { addr_of!((*ring).header) };
    if unsafe { (*header).magic } != SHARED_RING_MAGIC
        || unsafe { (*header).version } != SHARED_RING_VERSION
        || unsafe { (*header).slot_count } != SHARED_RING_SLOT_COUNT as u32
        || unsafe { (*header).reserved }
            .iter()
            .any(|value| *value != 0)
    {
        return Err(SharedRingError::InvalidHeader);
    }
    Ok(unsafe { (*header).generation })
}

/// Pushes one frontend-to-backend request.
///
/// # Safety
/// The caller must be the only request producer and `ring` must stay mapped.
pub unsafe fn push_request(
    ring: *mut SharedRingPage,
    message: SharedRingMessage,
) -> Result<(), SharedRingError> {
    let header = unsafe { addr_of!((*ring).header) };
    let slots = unsafe { addr_of_mut!((*ring).requests) } as *mut SharedRingMessage;
    unsafe {
        push(
            &(*header).request_producer,
            &(*header).request_consumer,
            slots,
            message,
        )
    }
}

/// Pops one frontend-to-backend request.
///
/// # Safety
/// The caller must be the only request consumer and `ring` must stay mapped.
pub unsafe fn pop_request(ring: *mut SharedRingPage) -> Result<SharedRingMessage, SharedRingError> {
    let header = unsafe { addr_of!((*ring).header) };
    let slots = unsafe { addr_of_mut!((*ring).requests) } as *mut SharedRingMessage;
    unsafe {
        pop(
            &(*header).request_producer,
            &(*header).request_consumer,
            slots,
        )
    }
}

/// Pushes one backend-to-frontend response.
///
/// # Safety
/// The caller must be the only response producer and `ring` must stay mapped.
pub unsafe fn push_response(
    ring: *mut SharedRingPage,
    message: SharedRingMessage,
) -> Result<(), SharedRingError> {
    let header = unsafe { addr_of!((*ring).header) };
    let slots = unsafe { addr_of_mut!((*ring).responses) } as *mut SharedRingMessage;
    unsafe {
        push(
            &(*header).response_producer,
            &(*header).response_consumer,
            slots,
            message,
        )
    }
}

/// Pops one backend-to-frontend response.
///
/// # Safety
/// The caller must be the only response consumer and `ring` must stay mapped.
pub unsafe fn pop_response(
    ring: *mut SharedRingPage,
) -> Result<SharedRingMessage, SharedRingError> {
    let header = unsafe { addr_of!((*ring).header) };
    let slots = unsafe { addr_of_mut!((*ring).responses) } as *mut SharedRingMessage;
    unsafe {
        pop(
            &(*header).response_producer,
            &(*header).response_consumer,
            slots,
        )
    }
}

unsafe fn push(
    producer: &AtomicU32,
    consumer: &AtomicU32,
    slots: *mut SharedRingMessage,
    message: SharedRingMessage,
) -> Result<(), SharedRingError> {
    if message.len as usize > SHARED_RING_PAYLOAD_SIZE {
        return Err(SharedRingError::CorruptEntry);
    }
    let producer_index = producer.load(Ordering::Relaxed);
    let consumer_index = consumer.load(Ordering::Acquire);
    if producer_index.wrapping_sub(consumer_index) >= SHARED_RING_SLOT_COUNT as u32 {
        return Err(SharedRingError::Full);
    }
    let slot = producer_index as usize % SHARED_RING_SLOT_COUNT;
    unsafe { write_volatile(slots.add(slot), message) };
    producer.store(producer_index.wrapping_add(1), Ordering::Release);
    Ok(())
}

unsafe fn pop(
    producer: &AtomicU32,
    consumer: &AtomicU32,
    slots: *mut SharedRingMessage,
) -> Result<SharedRingMessage, SharedRingError> {
    let consumer_index = consumer.load(Ordering::Relaxed);
    let producer_index = producer.load(Ordering::Acquire);
    if consumer_index == producer_index {
        return Err(SharedRingError::Empty);
    }
    let slot = consumer_index as usize % SHARED_RING_SLOT_COUNT;
    let message = unsafe { read_volatile(slots.add(slot)) };
    if message.len as usize > SHARED_RING_PAYLOAD_SIZE {
        return Err(SharedRingError::CorruptEntry);
    }
    consumer.store(consumer_index.wrapping_add(1), Ordering::Release);
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of, MaybeUninit};

    #[test]
    fn shared_ring_occupies_exactly_one_page() {
        assert_eq!(size_of::<SharedRingHeader>(), 64);
        assert_eq!(size_of::<SharedRingMessage>(), 64);
        assert_eq!(size_of::<SharedRingPage>(), 4096);
        assert_eq!(align_of::<SharedRingPage>(), 64);
    }

    #[test]
    fn request_and_response_round_trip() {
        let mut storage = MaybeUninit::<SharedRingPage>::uninit();
        let ring = storage.as_mut_ptr();
        unsafe { initialize(ring, 7) };
        assert_eq!(unsafe { validate(ring) }, Ok(7));

        let request = SharedRingMessage::new(1, 0, 42, b"request").unwrap();
        unsafe { push_request(ring, request).unwrap() };
        assert_eq!(unsafe { pop_request(ring) }, Ok(request));

        let response = SharedRingMessage::new(2, 0, 42, b"response").unwrap();
        unsafe { push_response(ring, response).unwrap() };
        assert_eq!(unsafe { pop_response(ring) }, Ok(response));
        assert_eq!(unsafe { pop_response(ring) }, Err(SharedRingError::Empty));
    }

    #[test]
    fn full_ring_does_not_overwrite_unread_messages() {
        let mut storage = MaybeUninit::<SharedRingPage>::uninit();
        let ring = storage.as_mut_ptr();
        unsafe { initialize(ring, 1) };
        let message = SharedRingMessage::new(1, 0, 1, b"x").unwrap();
        for _ in 0..SHARED_RING_SLOT_COUNT {
            unsafe { push_request(ring, message).unwrap() };
        }
        assert_eq!(
            unsafe { push_request(ring, message) },
            Err(SharedRingError::Full)
        );
    }
}
