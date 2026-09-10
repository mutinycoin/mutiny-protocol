use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DecodeError {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("VarUInt overflow")]
    Overflow,
    #[error("non-canonical VarUInt")]
    NonCanonicalVarUInt,
    #[error("VarUInt exceeds the maximum encoded length")]
    VarUIntTooLong,
}

pub trait ConsensusEncode {
    fn consensus_encode(&self, out: &mut Vec<u8>);
}

pub trait ConsensusDecode: Sized {
    fn consensus_decode(input: &mut &[u8]) -> Result<Self, DecodeError>;
}

#[inline]
pub fn write_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

#[inline]
pub fn write_u16_be(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[inline]
pub fn write_u32_be(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[inline]
pub fn write_u64_be(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[inline]
pub fn write_u256_be(out: &mut Vec<u8>, value: &[u8; 32]) {
    out.extend_from_slice(value);
}

fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8], DecodeError> {
    if input.len() < n {
        return Err(DecodeError::UnexpectedEof);
    }
    let (head, tail) = input.split_at(n);
    *input = tail;
    Ok(head)
}

#[inline]
pub fn read_u8(input: &mut &[u8]) -> Result<u8, DecodeError> {
    Ok(take(input, 1)?[0])
}

#[inline]
pub fn read_u16_be(input: &mut &[u8]) -> Result<u16, DecodeError> {
    let b: [u8; 2] = take(input, 2)?.try_into().expect("slice length checked");
    Ok(u16::from_be_bytes(b))
}

#[inline]
pub fn read_u32_be(input: &mut &[u8]) -> Result<u32, DecodeError> {
    let b: [u8; 4] = take(input, 4)?.try_into().expect("slice length checked");
    Ok(u32::from_be_bytes(b))
}

#[inline]
pub fn read_u64_be(input: &mut &[u8]) -> Result<u64, DecodeError> {
    let b: [u8; 8] = take(input, 8)?.try_into().expect("slice length checked");
    Ok(u64::from_be_bytes(b))
}

#[inline]
pub fn read_u256_be(input: &mut &[u8]) -> Result<[u8; 32], DecodeError> {
    Ok(take(input, 32)?.try_into().expect("slice length checked"))
}

/// Canonical unsigned LEB128-style VarUInt used by Mutiny V1.
pub fn write_varuint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

pub fn encode_varuint(value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    write_varuint(&mut out, value);
    out
}

/// Strict decoder. It re-encodes the parsed value and requires byte-for-byte
/// equality with the consumed representation, which rejects all non-minimal
/// encodings such as 80 00, 81 00, and ff 81 00.
pub fn read_varuint(input: &mut &[u8]) -> Result<u64, DecodeError> {
    let original = *input;
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut consumed = 0usize;

    loop {
        if consumed >= 10 {
            return Err(DecodeError::VarUIntTooLong);
        }
        let byte = *original.get(consumed).ok_or(DecodeError::UnexpectedEof)?;
        let payload = (byte & 0x7f) as u64;

        if shift == 63 && payload > 1 {
            return Err(DecodeError::Overflow);
        }
        if shift > 63 && payload != 0 {
            return Err(DecodeError::Overflow);
        }

        value |= payload.checked_shl(shift).ok_or(DecodeError::Overflow)?;
        consumed += 1;

        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }

    let canonical = encode_varuint(value);
    if canonical.as_slice() != &original[..consumed] {
        return Err(DecodeError::NonCanonicalVarUInt);
    }

    *input = &original[consumed..];
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_width_big_endian_vectors() {
        let mut out = Vec::new();
        write_u16_be(&mut out, 0);
        write_u16_be(&mut out, 1);
        write_u16_be(&mut out, 2047);
        write_u16_be(&mut out, 2048);
        write_u32_be(&mut out, 65536);
        write_u64_be(&mut out, 1 << 21);
        write_u64_be(&mut out, 12345);
        write_u64_be(&mut out, 12346);
        assert_eq!(
            hex::encode(out),
            "0000000107ff08000001000000000000002000000000000000003039000000000000303a"
        );
    }

    #[test]
    fn varuint_pack_a_vectors() {
        let vectors = [
            (0, "00"),
            (1, "01"),
            (127, "7f"),
            (128, "8001"),
            (255, "ff01"),
            (300, "ac02"),
            (16_384, "808001"),
        ];
        for (value, expected) in vectors {
            assert_eq!(hex::encode(encode_varuint(value)), expected);
            let bytes = hex::decode(expected).unwrap();
            let mut input = bytes.as_slice();
            assert_eq!(read_varuint(&mut input).unwrap(), value);
            assert!(input.is_empty());
        }
    }

    #[test]
    fn rejects_nonminimal_varuint() {
        for encoded in ["8000", "8100", "ff8100"] {
            let bytes = hex::decode(encoded).unwrap();
            let mut input = bytes.as_slice();
            assert_eq!(
                read_varuint(&mut input),
                Err(DecodeError::NonCanonicalVarUInt)
            );
        }
    }

    #[test]
    fn roundtrips_boundaries() {
        for value in [
            0,
            1,
            0x7f,
            0x80,
            0x3fff,
            0x4000,
            0x1f_ffff,
            0x20_0000,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let bytes = encode_varuint(value);
            let mut input = bytes.as_slice();
            assert_eq!(read_varuint(&mut input).unwrap(), value);
            assert!(input.is_empty());
        }
    }
}
