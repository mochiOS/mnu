//! Process creation metadata shared by mnu and its user space.

/// Marks an environment entry in the NUL-separated process creation metadata.
pub const ENVIRONMENT_PREFIX: &str = "__MNU_EXEC_ENV=";

/// Assigns an opaque security identity to a new process.
///
/// mnu uses this identity only for generic isolation mechanisms. The user space
/// that launches the process decides what the identity represents.
pub const SECURITY_IDENTITY_PREFIX: &str = "__MNU_EXEC_SECURITY_IDENTITY=";

/// Process role supplied to the manifest-based exec syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum ProcessRole {
    CoreService = 1,
    Service = 2,
    Application = 3,
    Driver = 4,
    Tool = 5,
    Unknown = 6,
}

impl ProcessRole {
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            1 => Some(Self::CoreService),
            2 => Some(Self::Service),
            3 => Some(Self::Application),
            4 => Some(Self::Driver),
            5 => Some(Self::Tool),
            6 => Some(Self::Unknown),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProcessRole;

    #[test]
    fn process_roles_round_trip_through_the_syscall_value() {
        for role in [
            ProcessRole::CoreService,
            ProcessRole::Service,
            ProcessRole::Application,
            ProcessRole::Driver,
            ProcessRole::Tool,
            ProcessRole::Unknown,
        ] {
            assert_eq!(ProcessRole::from_raw(role as u64), Some(role));
        }
        assert_eq!(ProcessRole::from_raw(0), None);
        assert_eq!(ProcessRole::from_raw(7), None);
    }
}
