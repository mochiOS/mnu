//! Process creation metadata shared by mnu and its user space.

/// Marks an environment entry in the NUL-separated process creation metadata.
pub const ENVIRONMENT_PREFIX: &str = "__MNU_EXEC_ENV=";

/// Assigns an opaque security identity to a new process.
///
/// mnu uses this identity only for generic isolation mechanisms. The user space
/// that launches the process decides what the identity represents.
pub const SECURITY_IDENTITY_PREFIX: &str = "__MNU_EXEC_SECURITY_IDENTITY=";

/// Kernel privilege requested by a manifest-based exec syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum ExecutionClass {
    Privileged = 2,
    Unprivileged = 3,
}

impl ExecutionClass {
    /// Values 1 and 4 through 6 are accepted for compatibility with the old
    /// role-based wire format. Their product meaning is not interpreted.
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            1 | 2 => Some(Self::Privileged),
            3..=6 => Some(Self::Unprivileged),
            _ => None,
        }
    }

    pub const fn as_raw(self) -> u64 {
        self as u64
    }
}

#[cfg(test)]
mod tests {
    use super::ExecutionClass;

    #[test]
    fn execution_classes_accept_current_and_legacy_values() {
        assert_eq!(
            ExecutionClass::from_raw(1),
            Some(ExecutionClass::Privileged)
        );
        assert_eq!(
            ExecutionClass::from_raw(2),
            Some(ExecutionClass::Privileged)
        );
        for raw in 3..=6 {
            assert_eq!(
                ExecutionClass::from_raw(raw),
                Some(ExecutionClass::Unprivileged)
            );
        }
        assert_eq!(ExecutionClass::Privileged.as_raw(), 2);
        assert_eq!(ExecutionClass::Unprivileged.as_raw(), 3);
        assert_eq!(ExecutionClass::from_raw(0), None);
        assert_eq!(ExecutionClass::from_raw(7), None);
    }
}
