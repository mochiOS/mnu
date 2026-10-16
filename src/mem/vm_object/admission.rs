//! Transferable queue ownership, without authority to modify backing data.
use super::super::object_io::{IntentError, IoIntent};
use super::*;
use mnu_abi::status::Error;

pub(crate) struct ProviderAdmission {
    key: ObjectKey,
    intent: SpinLock<IoIntent>,
}

fn error(error: IntentError) -> Error {
    match error {
        IntentError::Unavailable => Error::BackingFailure,
        IntentError::NoMemory => Error::ResourceUnavailable,
        IntentError::Exhausted => Error::LimitExceeded,
        IntentError::Consumed => Error::InvalidArgument,
    }
}

impl ProviderAdmission {
    pub(crate) fn new(key: ObjectKey) -> Result<Self, Error> {
        if !matches!(key, ObjectKey::Provider { identity, .. } if identity != 0) {
            return Err(Error::InvalidArgument);
        }
        let gate = PROVIDER_IO.lock().try_get(
            key,
            crate::mem::object_io_native::new_lock,
            Error::ResourceUnavailable,
        )?;
        let intent = gate.intent().map_err(error)?;
        Ok(Self {
            key,
            intent: SpinLock::new(intent),
        })
    }

    pub(crate) fn endpoint_parts(&self) -> (u64, u16, u64) {
        let ObjectKey::Provider {
            endpoint_thread_id,
            endpoint_slot,
            endpoint_generation,
            ..
        } = self.key
        else {
            unreachable!()
        };
        (endpoint_thread_id, endpoint_slot, endpoint_generation)
    }

    /// Only an authenticated endpoint owner can reach this native consumption
    /// path. Matching the full key prevents use with another resource/endpoint.
    pub(crate) fn acquire(&self, key: ObjectKey) -> Result<ProviderIoGuard, Error> {
        if self.key != key {
            return Err(Error::AccessDenied);
        }
        let mut intent = self.intent.try_lock().ok_or(Error::NotReady)?;
        let guard = intent
            .try_acquire()
            .map_err(error)?
            .ok_or(Error::NotReady)?;
        Ok(ProviderIoGuard { key, _guard: guard })
    }

    pub(crate) fn signals(&self) -> u64 {
        let Some(intent) = self.intent.try_lock() else {
            return 0;
        };
        match intent.ready() {
            Ok(true) => mnu_abi::HANDLE_SIGNAL_READABLE,
            Ok(false) => 0,
            Err(_) => mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
        }
    }

    pub(crate) fn register_waiter(&self, waiter: u64, maximum: usize) -> Result<(), Error> {
        self.intent
            .lock()
            .register_waiter(waiter, maximum)
            .map_err(error)
    }
    pub(crate) fn remove_waiter(&self, waiter: u64) {
        self.intent.lock().remove_waiter(waiter);
    }
}
