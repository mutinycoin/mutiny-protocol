//! Candidate node-owned canonical authority gate over a confirmed Worker channel.
//! No listener, key generation or typed application authorization.
use crate::hybrid_coordinator_v2::{Clock, Sample};
use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor, canonical_store_v2::CanonicalStore};
use mutiny_crypto_v2::{PublicKey, enrollment::Binding};
use mutiny_transport_v2::{
    Error, Result,
    worker_handshake_v2::{Authority, Channel, Confirmed},
};
use zeroize::Zeroizing;

struct Current {
    binding: Binding,
    node: PublicKey,
    generation: u64,
    height: u64,
    epoch: u64,
}
impl Current {
    fn load(
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        timestamp: u64,
    ) -> Result<Self> {
        let (work, binding, descriptor, epoch) = chain
            .current_worker_session(parent, license, worker, timestamp)
            .map_err(|_| Error::Context)?;
        let (node, generation) =
            PublicKey::decode_descriptor(&descriptor).map_err(|_| Error::Context)?;
        Ok(Self {
            binding,
            node,
            generation,
            height: work.parent_height.checked_add(1).ok_or(Error::Context)?,
            epoch,
        })
    }
    fn authority(&self) -> Authority<'_> {
        Authority {
            binding: &self.binding,
            node: &self.node,
            node_generation: self.generation,
            height: self.height,
            epoch: self.epoch,
        }
    }
}

/// One actor owns this gate and its clock. The expected parent must come from
/// its current canonical runtime, never a packet. Parent changes alone may keep
/// a transport channel alive; current assignment/descriptor/expiry cannot.
pub struct CanonicalWorkerChannel {
    channel: Option<Channel>,
    genesis: Hash,
    fingerprint: Hash,
    license: Hash,
    worker: Hash,
    previous: Sample,
}
impl CanonicalWorkerChannel {
    pub(crate) fn scope(&self) -> Result<crate::worker_protocol_v2::Scope> {
        self.channel.as_ref().ok_or(Error::Context)?;
        Ok(crate::worker_protocol_v2::Scope {
            genesis: self.genesis,
            fingerprint: self.fingerprint,
            license: self.license,
            worker: self.worker,
        })
    }
    pub(crate) fn worker_identity(&self) -> Result<Hash> {
        self.channel.as_ref().ok_or(Error::Context)?;
        Ok(self.worker)
    }
    /// The Node Finished tag is released only after fresh canonical activation.
    /// A failed attempt consumes the pending handshake and its ephemeral keys.
    pub fn finish(
        pending: mutiny_transport_v2::worker_handshake_v2::NodePending,
        finish: &[u8],
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        clock: &mut impl Clock,
    ) -> Result<(Self, [u8; 16])> {
        let (confirmed, tag) = pending.finish(finish)?;
        let channel = Self::activate(confirmed, chain, parent, license, worker, clock)?;
        Ok((channel, tag))
    }
    pub fn activate(
        confirmed: Confirmed,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        clock: &mut impl Clock,
    ) -> Result<Self> {
        if confirmed.is_worker_endpoint() {
            return Err(Error::Context);
        }
        let previous = clock.sample().map_err(|_| Error::Context)?;
        let current = Current::load(chain, parent, license, worker, previous.unix_ms / 1000)?;
        let channel = confirmed.into_channel(&current.authority())?;
        let mut out = Self {
            channel: Some(channel),
            genesis: current.binding.genesis,
            fingerprint: current.binding.fingerprint,
            license,
            worker,
            previous,
        };
        out.check(chain, parent, clock)?;
        Ok(out)
    }
    pub fn close(&mut self) {
        if let Some(mut channel) = self.channel.take() {
            channel.close();
        }
    }
    fn current(
        &mut self,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
    ) -> Result<Current> {
        if self.channel.is_none() {
            return Err(Error::Context);
        }
        let now = clock.sample().map_err(|_| Error::Context)?;
        if now.monotonic_ms < self.previous.monotonic_ms || now.unix_ms < self.previous.unix_ms {
            return Err(Error::Context);
        }
        self.previous = now;
        Current::load(chain, parent, self.license, self.worker, now.unix_ms / 1000)
    }
    /// Idle owner tick as well as pre/post-operation gate. Failure retires keys
    /// permanently; receiving a later good clock sample cannot reopen this gate.
    pub fn check(
        &mut self,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
    ) -> Result<()> {
        let result = (|| {
            let current = self.current(chain, parent, clock)?;
            self.channel
                .as_mut()
                .ok_or(Error::Context)?
                .validate_current(&current.authority())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn seal(
        &mut self,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let result = (|| {
            let current = self.current(chain, parent, clock)?;
            let frame = self
                .channel
                .as_mut()
                .ok_or(Error::Context)?
                .seal(&current.authority(), payload)?;
            self.check(chain, parent, clock)?;
            Ok(frame)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// AEAD authentication is not work or consensus authorization. The caller
    /// must still decode bounded typed messages and run their independent checks.
    pub fn open(
        &mut self,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
        frame: &[u8],
    ) -> Result<Vec<u8>> {
        let result = (|| {
            let current = self.current(chain, parent, clock)?;
            let mut plain = Zeroizing::new(
                self.channel
                    .as_mut()
                    .ok_or(Error::Context)?
                    .open(&current.authority(), frame)?,
            );
            self.check(chain, parent, clock)?;
            Ok(std::mem::take(&mut *plain))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
impl Drop for CanonicalWorkerChannel {
    fn drop(&mut self) {
        self.close();
    }
}
