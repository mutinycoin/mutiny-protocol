//! SOURCE-ONLY Path B local workflow target. Its synthetic TEST-VALUE adapter
//! tests state/response boundaries, not MakeCredential crypto, physical TPM
//! activation, physical equivalence, canonical admission, or execution locality.
//! No compiler or test result is claimed by the prepared source.
#[path = "../src/credential_activation_workflow.rs"]
mod credential_activation_workflow;
