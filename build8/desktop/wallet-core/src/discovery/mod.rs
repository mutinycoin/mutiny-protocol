//! Read-only lookups over a verified `State`, one file per area. Each is filled by the phase that
//! needs it; none of them authenticates the state (the caller verifies the parent state root first).
pub mod bonds;
pub mod dividends;
pub mod licenses;
pub mod locks;
