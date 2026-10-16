//! Bounded owner of an already accepted Worker socket until key confirmation.
//! Caller selects the expected canonical License/Worker and bounds/rate-limits
//! pending sockets before construction. No listener, selector or reconnect.
use crate::{
    hybrid_coordinator_v2::{Clock, Sample},
    node_custody_v2::EncryptedNodeKey,
    software_coordinator_custody_v2::EncryptedCoordinatorKey,
    worker_carrier_v2::{Carrier, NonblockingIo},
    worker_context_router_v2::Routed,
    worker_current_channel_v2::CanonicalWorkerChannel,
    worker_pending_budget_v2::Permit,
    worker_session_custody_v2::WorkerSessionSigner,
};
use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor, canonical_store_v2::CanonicalStore};
use mutiny_transport_v2::{
    Error, Result,
    worker_context_v2::{Context, HELLO_LEN},
    worker_handshake_v2::{NodePending, WORKER_FINISH_LEN},
};
use std::{
    io::ErrorKind,
    time::{Duration, Instant},
};
use zeroize::Zeroize;

const LIMIT: Duration = Duration::from_secs(60);
// Nested channel activation must continue the handshake's clock history, not
// establish a new baseline that could hide a transient rollback.
struct ContinuingClock<'a, C: Clock> {
    clock: &'a mut C,
    last: Sample,
    first_ms: u64,
    began: Instant,
    failed: bool,
}
impl<C: Clock> Clock for ContinuingClock<'_, C> {
    fn sample(&mut self) -> std::result::Result<Sample, String> {
        if self.failed {
            return Err("Worker handshake clock retired".into());
        }
        let now = match self.clock.sample() {
            Ok(now) => now,
            Err(e) => {
                self.failed = true;
                return Err(e);
            }
        };
        if now.monotonic_ms < self.last.monotonic_ms
            || now.unix_ms < self.last.unix_ms
            || now
                .monotonic_ms
                .checked_sub(self.first_ms)
                .is_none_or(|n| n >= 60_000)
            || self.began.elapsed() >= LIMIT
        {
            self.failed = true;
            return Err("Worker handshake clock/deadline rejected".into());
        }
        self.last = now;
        Ok(now)
    }
}
#[derive(Clone, Copy)]
pub enum Custody<'a> {
    Physical(&'a EncryptedNodeKey),
    Software(&'a EncryptedCoordinatorKey),
}
impl<'a> Custody<'a> {
    fn signer(
        self,
        chain: &'a CanonicalStore,
        parent: &'a FinalizedAnchor,
        license: Hash,
        worker: Hash,
        timestamp: u64,
    ) -> Result<(Context, WorkerSessionSigner<'a>)> {
        match self {
            Self::Physical(k) => {
                WorkerSessionSigner::physical(k, chain, parent, license, worker, timestamp)
            }
            Self::Software(k) => {
                WorkerSessionSigner::software(k, chain, parent, license, worker, timestamp)
            }
        }
    }
}
enum Phase {
    Hello,
    Response,
    Finish,
    Confirmation,
    Closed,
}
pub struct Handshake<I: NonblockingIo> {
    io: Option<I>,
    context: Context,
    license: Hash,
    worker: Hash,
    began: Instant,
    first: Sample,
    previous: Sample,
    phase: Phase,
    input: Vec<u8>,
    used: usize,
    output: Vec<u8>,
    sent: usize,
    pending: Option<NodePending>,
    channel: Option<CanonicalWorkerChannel>,
    permit: Option<Permit>,
    /// Diagnostic only (Delivery 1): (label, milliseconds). `at:` entries are wall-clock time since
    /// the 60 s deadline began; `cost:` entries are the duration of one cryptographic phase.
    /// It never influences any decision and holds no secret.
    timings: Vec<(&'static str, u64)>,
}
impl<I: NonblockingIo> Handshake<I> {
    /// Continues the exact Hello prefix read by the bounded public router.
    pub fn begin_routed(
        routed: Routed<I>,
        key: Custody<'_>,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
    ) -> Result<Self> {
        let (io, permit, prefix, route) = routed.take_parts()?;
        let mut owner = Self::begin_admitted(
            io,
            permit,
            key,
            chain,
            parent,
            route.license,
            route.worker,
            clock,
        )?;
        if prefix[..2] != [2, 1] || prefix[2..] != owner.context.id() {
            return Err(Error::Context); // Drop closes the socket and releases capacity.
        }
        owner.input[..prefix.len()].copy_from_slice(&prefix);
        owner.used = prefix.len();
        Ok(owner)
    }
    pub fn begin(
        io: I,
        key: Custody<'_>,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        clock: &mut impl Clock,
    ) -> Result<Self> {
        Self::begin_inner(io, None, key, chain, parent, license, worker, clock)
    }
    /// Retains the pending reservation through confirmation. Its original time
    /// includes public-context routing. Caller separately bounds active carriers.
    pub fn begin_admitted(
        io: I,
        permit: Permit,
        key: Custody<'_>,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        clock: &mut impl Clock,
    ) -> Result<Self> {
        Self::begin_inner(io, Some(permit), key, chain, parent, license, worker, clock)
    }
    fn begin_inner(
        mut io: I,
        permit: Option<Permit>,
        key: Custody<'_>,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        clock: &mut impl Clock,
    ) -> Result<Self> {
        let setup_started = Instant::now();
        let mut began = Instant::now();
        let initial = (|| {
            if let Some(p) = &permit {
                if p.claimed_worker().map_err(|_| Error::Context)? != worker {
                    return Err(Error::Context);
                }
                began = p.began().map_err(|_| Error::Expired)?;
            }
            let first = clock.sample().map_err(|_| Error::Context)?;
            let (context, _) = key.signer(chain, parent, license, worker, first.unix_ms / 1000)?;
            if began.elapsed() >= LIMIT {
                return Err(Error::Expired);
            }
            Ok((first, context))
        })();
        let (first, context) = match initial {
            Ok(v) => v,
            Err(e) => {
                io.close();
                return Err(e);
            }
        };
        let setup_ms = setup_started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        Ok(Self {
            io: Some(io),
            context,
            license,
            worker,
            began,
            first,
            previous: first,
            phase: Phase::Hello,
            input: vec![0; HELLO_LEN],
            used: 0,
            output: Vec::new(),
            sent: 0,
            pending: None,
            channel: None,
            permit,
            timings: vec![("cost:begin", setup_ms)],
        })
    }
    /// Diagnostic phase timings recorded so far (see the field documentation).
    pub fn phase_timings(&self) -> &[(&'static str, u64)] {
        &self.timings
    }
    fn mark(&mut self, label: &'static str) {
        let ms = self.began.elapsed().as_millis().min(u64::MAX as u128) as u64;
        self.timings.push((label, ms));
    }
    pub fn close(&mut self) {
        self.phase = Phase::Closed;
        if let Some(mut io) = self.io.take() {
            io.close();
        }
        if let Some(mut channel) = self.channel.take() {
            channel.close();
        }
        self.pending = None;
        self.input.zeroize();
        self.output.zeroize();
        self.input = Vec::new();
        self.output = Vec::new();
        self.used = 0;
        self.sent = 0;
        self.permit = None;
    }
    fn sample(&mut self, clock: &mut impl Clock) -> Result<Sample> {
        if let Some(p) = &self.permit {
            p.check().map_err(|_| Error::Context)?;
        }
        if matches!(self.phase, Phase::Closed) || self.io.is_none() {
            return Err(Error::Context);
        }
        if self.began.elapsed() >= LIMIT {
            return Err(Error::Expired);
        }
        let now = clock.sample().map_err(|_| Error::Context)?;
        if now.monotonic_ms < self.previous.monotonic_ms || now.unix_ms < self.previous.unix_ms {
            return Err(Error::Context);
        }
        if now
            .monotonic_ms
            .checked_sub(self.first.monotonic_ms)
            .ok_or(Error::Context)?
            >= 60_000
        {
            return Err(Error::Expired);
        }
        self.previous = now;
        Ok(now)
    }
    fn current<'a>(
        &mut self,
        key: Custody<'a>,
        chain: &'a CanonicalStore,
        parent: &'a FinalizedAnchor,
        clock: &mut impl Clock,
    ) -> Result<WorkerSessionSigner<'a>> {
        let now = self.sample(clock)?;
        let (context, signer) =
            key.signer(chain, parent, self.license, self.worker, now.unix_ms / 1000)?;
        if context.id() != self.context.id() {
            return Err(Error::Context);
        }
        if self.began.elapsed() >= LIMIT {
            return Err(Error::Expired);
        }
        Ok(signer)
    }
    fn check_channel(
        &mut self,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
    ) -> Result<()> {
        if let Some(channel) = self.channel.as_mut() {
            let mut guarded = ContinuingClock {
                clock,
                last: self.previous,
                first_ms: self.first.monotonic_ms,
                began: self.began,
                failed: false,
            };
            let result = channel.check(chain, parent, &mut guarded);
            self.previous = guarded.last;
            result?;
        }
        if self.began.elapsed() >= LIMIT {
            return Err(Error::Expired);
        }
        Ok(())
    }
    /// One nonblocking I/O call at most, with one bounded cryptographic phase
    /// transition. Every prefix shares the original60-second deadline.
    /// A returned carrier is the only transfer of socket/session ownership.
    pub fn step(
        &mut self,
        key: Custody<'_>,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
    ) -> Result<Option<Carrier<I>>> {
        let result = (|| {
            let signer = self.current(key, chain, parent, clock)?;
            match self.phase {
                Phase::Hello | Phase::Finish => {
                    let wanted = if matches!(self.phase, Phase::Hello) {
                        HELLO_LEN
                    } else {
                        WORKER_FINISH_LEN
                    };
                    let remaining = wanted - self.used;
                    match self
                        .io
                        .as_mut()
                        .ok_or(Error::Context)?
                        .read(&mut self.input[self.used..wanted])
                    {
                        Ok(n) if n > 0 && n <= remaining => self.used += n,
                        Err(e)
                            if matches!(
                                e.kind(),
                                ErrorKind::WouldBlock | ErrorKind::Interrupted
                            ) => {}
                        _ => return Err(Error::Context),
                    }
                    self.current(key, chain, parent, clock)?;
                    if self.used != wanted {
                        return Ok(None);
                    }
                    if matches!(self.phase, Phase::Hello) {
                        let started = Instant::now();
                        let (pending, response) = NodePending::accept(
                            self.context.clone(),
                            &signer,
                            &self.input[..wanted],
                        )?;
                        let cost = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                        self.timings.push(("cost:accept_hello", cost));
                        self.current(key, chain, parent, clock)?;
                        self.pending = Some(pending);
                        self.output = response;
                        self.phase = Phase::Response;
                        self.mark("at:hello_accepted");
                    } else {
                        let pending = self.pending.take().ok_or(Error::Context)?;
                        let started = Instant::now();
                        let mut guarded = ContinuingClock {
                            clock,
                            last: self.previous,
                            first_ms: self.first.monotonic_ms,
                            began: self.began,
                            failed: false,
                        };
                        let finished = CanonicalWorkerChannel::finish(
                            pending,
                            &self.input[..wanted],
                            chain,
                            parent,
                            self.license,
                            self.worker,
                            &mut guarded,
                        );
                        self.previous = guarded.last;
                        let cost = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                        self.timings.push(("cost:finish_and_activate", cost));
                        let (channel, tag) = finished?;
                        self.current(key, chain, parent, clock)?;
                        self.channel = Some(channel);
                        self.output = tag.to_vec();
                        self.phase = Phase::Confirmation;
                        self.mark("at:finish_verified");
                    }
                    self.sent = 0;
                    self.used = 0;
                    // Vec::zeroize clears its length; the next fixed-size
                    // phase needs this allocation's initialized slice intact.
                    self.input.as_mut_slice().zeroize();
                }
                Phase::Response | Phase::Confirmation => {
                    self.check_channel(chain, parent, clock)?;
                    let remaining = self.output.len() - self.sent;
                    match self
                        .io
                        .as_mut()
                        .ok_or(Error::Context)?
                        .write(&self.output[self.sent..])
                    {
                        Ok(n) if n > 0 && n <= remaining => self.sent += n,
                        Err(e)
                            if matches!(
                                e.kind(),
                                ErrorKind::WouldBlock | ErrorKind::Interrupted
                            ) => {}
                        _ => return Err(Error::Context),
                    }
                    self.current(key, chain, parent, clock)?;
                    self.check_channel(chain, parent, clock)?;
                    if self.sent != self.output.len() {
                        return Ok(None);
                    }
                    self.output.zeroize();
                    self.output.clear();
                    self.sent = 0;
                    if matches!(self.phase, Phase::Response) {
                        self.phase = Phase::Finish;
                        self.mark("at:response_sent");
                    } else {
                        let channel = self.channel.take().ok_or(Error::Context)?;
                        let io = self.io.take().ok_or(Error::Context)?;
                        self.phase = Phase::Closed;
                        self.mark("at:confirmation_sent");
                        return Ok(Some(Carrier::new(io, channel)));
                    }
                }
                Phase::Closed => return Err(Error::Context),
            }
            Ok(None)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
impl<I: NonblockingIo> Drop for Handshake<I> {
    fn drop(&mut self) {
        self.close();
    }
}
