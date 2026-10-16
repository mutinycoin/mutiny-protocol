//! Nonshipping activation TEST host, included only by the explicit integration
//! target. No module/feature/factory is registered in the ordinary Node graph.
//! Actual tools/TPM interoperability is pending; parser models are not activation.
pub mod exchange;
pub mod channel;
pub mod socket;
pub mod delivery;
pub mod bridge;
pub mod native_controls;
pub mod provider;
pub mod tools_format;
#[cfg(target_os = "linux")]
pub mod linux_tools;
#[cfg(target_os = "linux")]
pub mod linux_interop;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Bounds, Codec, Context, Authority, Production, Current,
    ToolPin, ToolIo, ToolExit, ActivationRejected, Expired, Endpoint, Response, Unsupported }
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(target_os = "linux")]
pub mod linux_policy_interop;
