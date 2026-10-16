//! Governing external input is UNAVAILABLE. This distinct type reserves the
//! actual accepted issuer boundary without fabricating a constructor from
//! administrator, SSH, clock, public descriptor or TEST authority.
#![cfg(target_os="linux")]
/// No accepted existing source mechanism currently supplies a variant. The
/// installed public startup explicitly refuses before any native effect.
/// Future issuance must implement the exact accepted source artifact/principal
/// and lifetime/ownership contract and preserve the existing one-shot codec.
pub(crate) enum InstalledSecretSourceRegistration {}

/// Governing external-input classification, shared by the binary entry and
/// actual conditional factory controller. It performs no native acquisition,
/// worker spawn, read, secret import, replacement-key creation or initialization.
pub(crate) fn require_registered_source()->std::result::Result<InstalledSecretSourceRegistration,String>{
    Err("installed Node/Continuity unlock secret source unavailable: accepted source kind, issuer pins and ownership/cancellation/close contract required".into())
}
