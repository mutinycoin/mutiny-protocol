//! Typed host failure only; no new peer wire or session timing policy.
use std::fmt;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerFailure {
    /// The transport's actual lifetime error, never an I/O timeout or text match.
    SessionExpired,
    Other(String),
}
pub type PeerResult<T> = Result<T, PeerFailure>;
impl PeerFailure {
    pub fn transport(context: &str, error: mutiny_transport_v2::Error) -> Self {
        match error {
            mutiny_transport_v2::Error::Expired => Self::SessionExpired,
            error => Self::Other(format!("{context}: {error:?}")),
        }
    }
    pub fn carrier(context: &str, error: mutiny_transport_v2::tcp::Error) -> Self {
        match error {
            mutiny_transport_v2::tcp::Error::Transport(error) => Self::transport(context, error),
            error => Self::Other(format!("{context}: {error:?}")),
        }
    }
    pub fn dispatch(context: &str, error: crate::hybrid_dispatch_v2::DispatchError) -> Self {
        match error {
            crate::hybrid_dispatch_v2::DispatchError::Transport(error) => Self::transport(context, error),
            error => Self::Other(format!("{context}: {error:?}")),
        }
    }
}
impl From<String> for PeerFailure {
    fn from(value: String) -> Self { Self::Other(value) }
}
impl From<&str> for PeerFailure {
    fn from(value: &str) -> Self { Self::Other(value.into()) }
}
impl fmt::Display for PeerFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionExpired => f.write_str("Peer session expired"),
            Self::Other(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for PeerFailure {}
impl From<PeerFailure> for String {
    fn from(value: PeerFailure) -> Self { value.to_string() }
}
impl From<PeerFailure> for crate::hybrid_dispatch_v2::DispatchError {
    fn from(value: PeerFailure) -> Self {
        match value {
            PeerFailure::SessionExpired => Self::Transport(mutiny_transport_v2::Error::Expired),
            PeerFailure::Other(message) => Self::Admission(message),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_transport_v2::{Error, tcp};
    #[test]
    fn g3_expiry_is_typed_and_all_other_transport_errors_stay_other() {
        assert_eq!(PeerFailure::transport("receive", Error::Expired), PeerFailure::SessionExpired);
        for error in [Error::Encoding, Error::Context, Error::Crypto, Error::Replay, Error::Limit, Error::Storage] {
            assert!(matches!(PeerFailure::transport("receive", error), PeerFailure::Other(_)));
        }
        assert!(matches!(PeerFailure::from("Expired"), PeerFailure::Other(_)));
        assert!(matches!(PeerFailure::from("Peer receive: Expired".to_string()), PeerFailure::Other(_)));
    }
    #[test]
    fn g3_carrier_deadline_io_and_closed_are_not_session_expiry() {
        assert_eq!(PeerFailure::carrier("tcp", tcp::Error::Transport(Error::Expired)), PeerFailure::SessionExpired);
        for error in [tcp::Error::Deadline, tcp::Error::Closed, tcp::Error::Length,
            tcp::Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "Expired"))] {
            assert!(matches!(PeerFailure::carrier("tcp", error), PeerFailure::Other(_)));
        }
    }
    #[test]
    fn g3_dispatch_roundtrip_preserves_only_the_expiry_discriminant() {
        let dispatch: crate::hybrid_dispatch_v2::DispatchError = PeerFailure::SessionExpired.into();
        assert_eq!(PeerFailure::dispatch("dispatch", dispatch), PeerFailure::SessionExpired);
        let dispatch: crate::hybrid_dispatch_v2::DispatchError = PeerFailure::Other("Expired".into()).into();
        assert!(matches!(PeerFailure::dispatch("dispatch", dispatch), PeerFailure::Other(_)));
        assert!(matches!(PeerFailure::dispatch("dispatch", crate::hybrid_dispatch_v2::DispatchError::ActorDeadline), PeerFailure::Other(_)));
    }
    #[test]
    fn g3_string_compatibility_remains_diagnostic_only() {
        let message: String = PeerFailure::SessionExpired.into();
        assert_eq!(message, "Peer session expired");
        assert_eq!(String::from(PeerFailure::Other("original diagnostic".into())), "original diagnostic");
    }
}

