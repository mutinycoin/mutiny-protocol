//! Unauthenticated handshake framing. Completion conveys no trust; the pinned
//! hybrid handshake and Finished verification remain mandatory at the caller.
use crate::handshake::{CLIENT_FINISH_LEN, HELLO_LEN, RESPONSE_LEN};
use crate::{Error, Result, primitives::random};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
const HEADER: usize = 69;
pub const PAYLOAD: usize = 255 - HEADER;
const MAX_FLIGHTS: usize = 4;
const MAX_PEERS: usize = 64;
const LIFETIME: Duration = Duration::from_secs(600);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    Response = 2,
    ClientFinish = 3,
    ServerFinish = 4,
}
impl Kind {
    fn length(self) -> usize {
        match self {
            Self::Hello => HELLO_LEN,
            Self::Response => RESPONSE_LEN,
            Self::ClientFinish => CLIENT_FINISH_LEN,
            Self::ServerFinish => 16,
        }
    }
    fn parse(x: u8) -> Result<Self> {
        match x {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Response),
            3 => Ok(Self::ClientFinish),
            4 => Ok(Self::ServerFinish),
            _ => Err(Error::Encoding),
        }
    }
}
/// Fresh public flight nonce. Never reused as an AEAD nonce or identity proof.
pub fn fragment(
    tag: [u8; 16],
    sender: [u8; 32],
    kind: Kind,
    message: &[u8],
) -> Result<Vec<Vec<u8>>> {
    if message.len() != kind.length() || tag == [0; 16] || sender == [0; 32] {
        return Err(Error::Encoding);
    }
    let flight: [u8; 16] = *random::<16>()?;
    if flight == [0; 16] {
        return Err(Error::Crypto);
    }
    let count = message.len().div_ceil(PAYLOAD);
    let mut frames = Vec::with_capacity(count);
    for (index, part) in message.chunks(PAYLOAD).enumerate() {
        let mut frame = Vec::with_capacity(HEADER + part.len());
        frame.extend([2, kind as u8]);
        frame.extend(tag);
        frame.extend(sender);
        frame.extend(flight);
        frame.extend([index as u8, count as u8, part.len() as u8]);
        frame.extend(part);
        frames.push(frame);
    }
    Ok(frames)
}
struct Flight {
    id: [u8; 16],
    kind: Kind,
    started: Instant,
    parts: Vec<Option<Vec<u8>>>,
}
pub struct Reassembler {
    tag: [u8; 16],
    peers: BTreeSet<[u8; 32]>,
    flights: BTreeMap<[u8; 32], Flight>,
}
impl Reassembler {
    pub fn new(tag: [u8; 16], peers: Vec<[u8; 32]>) -> Result<Self> {
        if tag == [0; 16] || peers.is_empty() || peers.len() > MAX_PEERS || peers.contains(&[0; 32])
        {
            return Err(Error::Context);
        }
        let n = peers.len();
        let peers: BTreeSet<_> = peers.into_iter().collect();
        if peers.len() != n {
            return Err(Error::Context);
        }
        Ok(Self {
            tag,
            peers,
            flights: BTreeMap::new(),
        })
    }
    pub fn expire(&mut self) {
        self.expire_at(Instant::now());
    }
    fn expire_at(&mut self, now: Instant) {
        self.flights
            .retain(|_, f| now.duration_since(f.started) <= LIFETIME);
    }
    /// Caller fixes the expected handshake phase. Peer and phase headers are
    /// untrusted routing hints. One incomplete flight per pinned peer; no remote
    /// replacement/timeout extension, even for conflicting duplicate fragments.
    pub fn receive(&mut self, expected: Kind, frame: &[u8]) -> Result<Option<([u8; 32], Vec<u8>)>> {
        self.expire();
        if frame.len() < HEADER + 1 || frame.len() > 255 || frame[0] != 2 {
            return Err(Error::Encoding);
        }
        let kind = Kind::parse(frame[1])?;
        if kind != expected || frame[2..18] != self.tag {
            return Err(Error::Context);
        }
        let peer: [u8; 32] = frame[18..50].try_into().unwrap();
        if !self.peers.contains(&peer) {
            return Err(Error::Context);
        }
        let id: [u8; 16] = frame[50..66].try_into().unwrap();
        if id == [0; 16] {
            return Err(Error::Encoding);
        }
        let index = frame[66] as usize;
        let count = frame[67] as usize;
        let n = frame[68] as usize;
        if count != kind.length().div_ceil(PAYLOAD)
            || index >= count
            || n != kind.length().saturating_sub(index * PAYLOAD).min(PAYLOAD)
            || frame.len() != HEADER + n
        {
            return Err(Error::Encoding);
        }
        if !self.flights.contains_key(&peer) {
            if self.flights.len() >= MAX_FLIGHTS {
                return Err(Error::Limit);
            }
            self.flights.insert(
                peer,
                Flight {
                    id,
                    kind,
                    started: Instant::now(),
                    parts: vec![None; count],
                },
            );
        }
        let f = self.flights.get_mut(&peer).unwrap();
        if f.id != id || f.kind != kind {
            return Err(Error::Context);
        }
        if let Some(old) = &f.parts[index] {
            if old != &frame[HEADER..] {
                return Err(Error::Context);
            }
            return Ok(None);
        }
        f.parts[index] = Some(frame[HEADER..].to_vec());
        if f.parts.iter().any(Option::is_none) {
            return Ok(None);
        }
        let f = self.flights.remove(&peer).unwrap();
        let mut result = Vec::with_capacity(kind.length());
        for part in f.parts {
            result.extend(part.unwrap());
        }
        Ok(Some((peer, result)))
    }
    pub fn pending_count(&self) -> usize {
        self.flights.len()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_flights_reorder_loss_duplicate_conflict_bounds_and_expiry() {
        for kind in [
            Kind::Hello,
            Kind::Response,
            Kind::ClientFinish,
            Kind::ServerFinish,
        ] {
            let raw: Vec<u8> = (0..kind.length()).map(|i| (i % 251) as u8).collect();
            let frames = fragment([1; 16], [2; 32], kind, &raw).unwrap();
            let mut r = Reassembler::new([1; 16], vec![[2; 32]]).unwrap();
            for frame in frames.iter().skip(1).rev() {
                assert!(r.receive(kind, frame).unwrap().is_none());
                assert!(r.receive(kind, frame).unwrap().is_none());
            }
            if frames.len() > 1 {
                let mut bad = frames[1].clone();
                bad[HEADER] ^= 1;
                assert_eq!(r.receive(kind, &bad).unwrap_err(), Error::Context);
            }
            let (peer, result) = r.receive(kind, &frames[0]).unwrap().unwrap();
            assert_eq!(peer, [2; 32]);
            assert_eq!(result, raw);
            assert_eq!(r.pending_count(), 0);
            for pos in [0, 1, 2, 18, 66, 67, 68] {
                let mut bad = frames[0].clone();
                bad[pos] ^= 128;
                assert!(r.receive(kind, &bad).is_err());
            }
            for n in [0, HEADER, frames[0].len() - 1] {
                assert!(r.receive(kind, &frames[0][..n]).is_err());
            }
            let mut trailing = frames[0].clone();
            trailing.push(0);
            assert!(r.receive(kind, &trailing).is_err());
        }
        let mut r = Reassembler::new([1; 16], (1..=5).map(|i| [i; 32]).collect()).unwrap();
        for i in 1..=4 {
            let f = fragment([1; 16], [i; 32], Kind::Hello, &vec![0; HELLO_LEN]).unwrap();
            r.receive(Kind::Hello, &f[0]).unwrap();
        }
        let fifth = fragment([1; 16], [5; 32], Kind::Hello, &vec![0; HELLO_LEN]).unwrap();
        assert_eq!(r.receive(Kind::Hello, &fifth[0]).unwrap_err(), Error::Limit);
        r.expire_at(Instant::now() + LIFETIME + Duration::from_secs(1));
        assert_eq!(r.pending_count(), 0);
        r.receive(Kind::Hello, &fifth[0]).unwrap();
    }
}
