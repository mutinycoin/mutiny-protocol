//! Bounded public Hello routing before cryptographic authentication.
//! A route selects expected identities; it grants no session/mining authority.
use crate::{
    worker_carrier_v2::NonblockingIo,
    worker_pending_budget_v2::{Budget, Permit},
};
use mutiny_consensus_v8::Hash;
use mutiny_transport_v2::{Error, Result};
use std::{collections::BTreeMap, io::ErrorKind};

pub const PREFIX_LEN: usize = 66;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub license: Hash,
    pub worker: Hash,
}
/// Bounded routing snapshot assembled from public contexts. An old snapshot may
/// cause rejection; it cannot bypass the handshake's fresh canonical checks.
pub struct Routes(BTreeMap<[u8; 64], Route>);
impl Routes {
    pub fn new(entries: impl IntoIterator<Item = ([u8; 64], Route)>, limit: u16) -> Result<Self> {
        if limit == 0 {
            return Err(Error::Limit);
        }
        let mut map = BTreeMap::new();
        // Never collect an unbounded iterator before enforcing the local cap.
        for (context, route) in entries {
            if map.len() >= usize::from(limit) {
                return Err(Error::Limit);
            }
            if map.insert(context, route).is_some() {
                return Err(Error::Context);
            }
        }
        Ok(Self(map))
    }
    fn lookup(&self, prefix: &[u8; PREFIX_LEN]) -> Result<Route> {
        if prefix[..2] != [2, 1] {
            return Err(Error::Context);
        }
        let context: [u8; 64] = prefix[2..].try_into().map_err(|_| Error::Encoding)?;
        self.0.get(&context).copied().ok_or(Error::Context)
    }
}
pub struct Prefix<I: NonblockingIo> {
    io: Option<I>,
    permit: Option<Permit>,
    bytes: [u8; PREFIX_LEN],
    used: usize,
}
pub struct Routed<I: NonblockingIo> {
    io: Option<I>,
    permit: Option<Permit>,
    prefix: [u8; PREFIX_LEN],
    route: Route,
}
impl<I: NonblockingIo> Prefix<I> {
    pub fn begin(mut io: I, budget: &Budget) -> Result<Self> {
        let permit = match budget.reserve() {
            Ok(p) => p,
            Err(_) => {
                io.close();
                return Err(Error::Limit);
            }
        };
        Ok(Self {
            io: Some(io),
            permit: Some(permit),
            bytes: [0; PREFIX_LEN],
            used: 0,
        })
    }
    fn check(&self) -> Result<()> {
        self.permit
            .as_ref()
            .ok_or(Error::Context)?
            .check()
            .map_err(|_| Error::Expired)
    }
    /// One nonblocking read, at most66 bytes. No read-ahead or private signing.
    pub fn step(&mut self, routes: &Routes) -> Result<Option<Routed<I>>> {
        let result = (|| {
            self.check()?;
            let remaining = PREFIX_LEN - self.used;
            match self
                .io
                .as_mut()
                .ok_or(Error::Context)?
                .read(&mut self.bytes[self.used..])
            {
                Ok(n) if n > 0 && n <= remaining => self.used += n,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                _ => return Err(Error::Context),
            }
            self.check()?;
            if self.used != PREFIX_LEN {
                return Ok(None);
            }
            let route = routes.lookup(&self.bytes)?;
            self.permit
                .as_ref()
                .ok_or(Error::Context)?
                .claim(route.worker)
                .map_err(|_| Error::Limit)?;
            Ok(Some(Routed {
                io: self.io.take(),
                permit: self.permit.take(),
                prefix: self.bytes,
                route,
            }))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn close(&mut self) {
        if let Some(mut io) = self.io.take() {
            io.close();
        }
        self.permit = None;
        self.bytes.fill(0);
        self.used = 0;
    }
}
impl<I: NonblockingIo> Drop for Prefix<I> {
    fn drop(&mut self) {
        self.close();
    }
}
impl<I: NonblockingIo> Routed<I> {
    pub(crate) fn take_parts(mut self) -> Result<(I, Permit, [u8; PREFIX_LEN], Route)> {
        self.permit
            .as_ref()
            .ok_or(Error::Context)?
            .check()
            .map_err(|_| Error::Expired)?;
        let io = self.io.take().ok_or(Error::Context)?;
        let permit = self.permit.take().ok_or(Error::Context)?;
        Ok((io, permit, self.prefix, self.route))
    }
}
impl<I: NonblockingIo> Drop for Routed<I> {
    fn drop(&mut self) {
        if let Some(mut io) = self.io.take() {
            io.close();
        }
        self.permit = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker_pending_budget_v2::Limits;
    use std::{
        cell::RefCell,
        io::{self, Read, Write},
        rc::Rc,
    };
    #[derive(Default)]
    struct State {
        bytes: Vec<u8>,
        offset: usize,
        calls: usize,
        closed: bool,
        mode: u8,
    }
    struct Io(Rc<RefCell<State>>);
    impl Read for Io {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let mut s = self.0.borrow_mut();
            s.calls += 1;
            if s.mode == 1 {
                return Ok(out.len() + 1);
            }
            if s.mode == 2 {
                return Ok(0);
            }
            let n = out.len().min(7).min(s.bytes.len() - s.offset);
            if n == 0 {
                return Err(ErrorKind::WouldBlock.into());
            }
            out[..n].copy_from_slice(&s.bytes[s.offset..s.offset + n]);
            s.offset += n;
            Ok(n)
        }
    }
    impl Write for Io {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("routing must not write");
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl NonblockingIo for Io {
        fn close(&mut self) {
            self.0.borrow_mut().closed = true;
        }
    }
    fn budget() -> Budget {
        Budget::new(Limits {
            pending: 1,
            attempts_per_minute: 20,
            attempts_per_worker_per_minute: 2,
        })
        .unwrap()
    }
    fn fixture() -> (Routes, Vec<u8>, Route) {
        let route = Route {
            license: [1; 32],
            worker: [2; 32],
        };
        let routes = Routes::new([([3; 64], route)], 1).unwrap();
        let mut bytes = vec![2, 1];
        bytes.extend_from_slice(&[3; 64]);
        bytes.extend_from_slice(&[8; 100]);
        (routes, bytes, route)
    }
    #[test]
    fn partial_prefix_preserves_following_bytes_and_owned_permit() {
        let (routes, bytes, route) = fixture();
        let b = budget();
        let shared = Rc::new(RefCell::new(State {
            bytes,
            ..State::default()
        }));
        let mut p = Prefix::begin(Io(shared.clone()), &b).unwrap();
        assert!(b.reserve().is_err());
        let routed = loop {
            let before = shared.borrow().calls;
            let result = p.step(&routes).unwrap();
            assert_eq!(shared.borrow().calls, before + 1);
            if let Some(r) = result {
                break r;
            }
        };
        assert_eq!(shared.borrow().offset, PREFIX_LEN);
        drop(p);
        assert!(!shared.borrow().closed);
        let (mut io, permit, prefix, selected) = routed.take_parts().unwrap();
        assert_eq!(selected, route);
        assert_eq!(prefix[2..], [3; 64]);
        assert_eq!(permit.claimed_worker().unwrap(), route.worker);
        let mut rest = [0; 7];
        assert_eq!(io.read(&mut rest).unwrap(), 7);
        assert_eq!(rest, [8; 7]);
        io.close();
        drop(permit);
        assert!(b.reserve().is_ok());
    }
    #[test]
    fn malformed_unknown_eof_and_invalid_counts_close_without_handoff() {
        for scenario in 0..4 {
            let (routes, mut bytes, _) = fixture();
            if scenario == 0 {
                bytes[0] ^= 1;
            }
            if scenario == 1 {
                bytes[2] ^= 1;
            }
            let mode = if scenario == 2 {
                2
            } else if scenario == 3 {
                1
            } else {
                0
            };
            let shared = Rc::new(RefCell::new(State {
                bytes,
                mode,
                ..State::default()
            }));
            let b = budget();
            let mut p = Prefix::begin(Io(shared.clone()), &b).unwrap();
            for _ in 0..10 {
                match p.step(&routes) {
                    Ok(None) => {}
                    Err(_) => break,
                    Ok(Some(_)) => panic!("invalid handoff"),
                }
            }
            assert!(shared.borrow().closed);
            assert!(p.step(&routes).is_err());
            assert!(b.reserve().is_ok());
        }
    }
    #[test]
    fn drop_and_capacity_rejection_close_socket() {
        let b = budget();
        let (_, bytes, _) = fixture();
        let a = Rc::new(RefCell::new(State {
            bytes,
            ..State::default()
        }));
        let p = Prefix::begin(Io(a.clone()), &b).unwrap();
        let c = Rc::new(RefCell::new(State::default()));
        assert!(Prefix::begin(Io(c.clone()), &b).is_err());
        assert!(c.borrow().closed);
        drop(p);
        assert!(a.borrow().closed);
    }
    #[test]
    fn route_limit_and_duplicate_context_rejected() {
        let (_, _, r) = fixture();
        assert!(Routes::new([([3; 64], r)], 0).is_err());
        assert!(Routes::new([([3; 64], r), ([4; 64], r)], 1).is_err());
        assert!(Routes::new([([3; 64], r), ([3; 64], r)], 2).is_err());
    }
}
