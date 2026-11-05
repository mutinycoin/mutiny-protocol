# TEST-VALUE endorsement DER alias V1

Status: selected, candidate / UNFROZEN successor. This artifact defines only an
explicit TEST-VALUE rule. It grants no Production admission, activation,
hardware uniqueness, locality, signing, provisioning or publication authority.

The RuleManifestV1 selector name is the exact ASCII byte string
`TestValueEndorsementDerAliasV1`. Its value is SHA-256 of the exact UTF-8 bytes
of this artifact, including LF line endings and the final LF. The existing rule
manifest, root-set and class binding commitments remain mandatory. A different
selector commitment is refused. A Production-class parameter record carrying
the selector is refused even if no labelled root is present. An absent selector
retains the historical root-set interpretation; distinguished label bytes alone
never enable this rule. No new hash domain, operation kind or wire field exists.

In a selected TestValue-class record, every EndorsementRootSetV2 label is exactly
`BUILD8-TEST-DER-ALIAS-V1` followed by one NUL byte and the nonzero 32-byte SHA-256
of the exact root certificate DER. Its length is 57 bytes. The entry key remains
the historical `MUTINY-BUILD8-TEST-VALUE-ENDORSEMENT-ROOT-V2` domain hash of the
entire label. Wrong key, marker, width, zero DER digest or duplicate DER binding
is refused. Every entry's full AnchorConstraints remain committed unchanged.
The full selector, labels, logical RootIDs, DER digests and constraints are
immutable parameter inputs to Genesis identity and ProtocolFingerprint.

An opaque policy is derived only from validated immutable parameters. It supplies
the exact DER digest and the committed constraints to the existing certificate
and CRL procedures. Certificate signatures, complete path bytes, EK classes,
reference time, revocation checks and leaf/public-area identity checks are never
skipped. VerifiedEndorsement.anchor and path remain exact certificate DER hashes.
Only after a path is authenticated may its exact DER anchor translate through
the committed policy to the logical RootID named by a provenance identity. The
primary provenance root must equal the first identity's logical root. Each
identity root must match its authenticated path; LegacyTest's earlier profile
compatibility return cannot supply this evidence or an alternate alias.

Genesis public witness validation, admission and recovery dependency validation,
current and retired paths, activation material resolution, CRL signer anchors
and unused-root withdrawal all consume this same parameter-derived policy.
A2 certificate/key targets and retained path identities remain exact DER/key
hashes; a logical RootID is never substituted for a certificate target. An
unused-root judgment must authenticate its exact DER hash through the selected
anchor policy. Applicant bytes, caller booleans, ambient maps, OS trust stores
and peer receipts cannot select or alter a binding.

Historical absent-selector records and original artifacts are retained and
replayed with their original interpretation. Production's label/TEST-marker
refusals, native admission Scope/Material construction, physical qualification,
parent quorum, fresh activation and explicit local lifetime inputs remain in
force. This rule alone proves no physical TPM and creates no activation permit.
