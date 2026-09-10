use std::fmt;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Hex32Error {
    #[error("expected exactly 32 bytes")]
    WrongLength,
    #[error("invalid hex")]
    InvalidHex,
}

macro_rules! hash32_type {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            pub const ZERO: Self = Self([0u8; 32]);

            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub fn from_hex(s: &str) -> Result<Self, Hex32Error> {
                let bytes = hex::decode(s).map_err(|_| Hex32Error::InvalidHex)?;
                let arr: [u8; 32] = bytes.try_into().map_err(|_| Hex32Error::WrongLength)?;
                Ok(Self(arr))
            }

            pub fn to_hex(self) -> String {
                hex::encode(self.0)
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(value: [u8; 32]) -> Self {
                Self(value)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }
    };
}

hash32_type!(Hash256);
hash32_type!(BlockHash);
hash32_type!(TxId);
hash32_type!(WtxId);
hash32_type!(LicenseId);
hash32_type!(AddressId);
hash32_type!(NodeId);
hash32_type!(TreasuryId);
hash32_type!(StateRoot);
hash32_type!(OperationId);
hash32_type!(EvidenceId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Strikes(pub u64);

impl Strikes {
    pub const PER_MUT: u64 = 100_000_000;

    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
    }
}
