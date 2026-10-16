//! AEAD object delivery to bounded liveness semantics. No transport event counts
//! as a vote, participation or work lease. This candidate is not a socket service.
use crate::{hybrid_runtime_v2::HybridRuntime, hybrid_work_probes_v2::WorkProbes};
use mutiny_consensus_v8::{certificates::Decision, liveness_v2::Proof};
use mutiny_transport_v2::{
    object_link::{Event, ObjectLink},
    objects::ObjectKind,
};
pub enum ProbeEvent {
    Transport(Event),
    RequestQueued { receipt: Vec<u8> },
    FragmentAccepted { receipt: Vec<u8> },
}
fn err(e: impl std::fmt::Debug) -> String {
    format!("Hybrid probe dispatch: {e:?}")
}
/// Local resource policy: at most three signatures in one second, independently
/// of peer count. This timing does not create consensus or quorum authority.
#[derive(Default)]
pub struct ProbeSigner {
    last_tick: Option<u64>,
}
impl ProbeSigner {
    pub fn tick<B: mutiny_consensus_v8::counter_voter_v2::CounterSigningBackend>(
        &mut self,
        voter: &mut crate::hybrid_voter_v2::VotingRuntime<B>,
        pool: &mut WorkProbes,
        now_ms: u64,
    ) -> Result<usize, String> {
        if let Some(last) = self.last_tick {
            if now_ms < last {
                return Err("Probe signing clock regressed".into());
            }
            if now_ms - last < 1000 {
                return Ok(0);
            }
        }
        self.last_tick = Some(now_ms);
        let head = voter.validator().head().map_err(err)?;
        let (authority, root) = voter
            .validator()
            .chain
            .current_liveness(&head)
            .map_err(err)?;
        let pending = pool.pending(voter.signer_node(), &authority, root, now_ms)?;
        let mut signed = 0;
        for (peer, decision) in pending {
            let fragment = voter.sign_work_probe(&decision).map_err(err)?;
            voter
                .validator()
                .chain
                .current_liveness(&head)
                .map_err(err)?;
            pool.signed(
                peer,
                Proof {
                    decision,
                    fragments: vec![fragment],
                },
                &authority,
                root,
                now_ms,
            )?;
            signed += 1;
        }
        Ok(signed)
    }
}
/// `now_ms` is local monotonic service time. WorkGate acceptance and eventual work
/// release independently re-read trusted time after expensive verification.
pub fn receive(
    runtime: &HybridRuntime,
    pool: &mut WorkProbes,
    link: &mut ObjectLink,
    frame: &[u8],
    now_ms: u64,
) -> Result<ProbeEvent, String> {
    let event = link.receive(frame).map_err(err)?;
    dispatch(runtime, pool, link, event, now_ms)
}
/// Separate semantic dispatch from blocking socket receive. Event must come
/// from this link's authenticated receive path; caller owns the canonical actor.
pub fn dispatch(
    runtime: &HybridRuntime,
    pool: &mut WorkProbes,
    link: &mut ObjectLink,
    event: Event,
    now_ms: u64,
) -> Result<ProbeEvent, String> {
    let Event::Completed { offer, bytes } = &event else {
        return Ok(ProbeEvent::Transport(event));
    };
    if !matches!(
        offer.kind,
        ObjectKind::WorkProbeRequest | ObjectKind::WorkProbeFragment
    ) {
        return Ok(ProbeEvent::Transport(event));
    }
    // Peers cannot name another peer in their application payload.
    let peer = link.peer_id();
    let result = (|| {
        let head = runtime.head().map_err(err)?;
        let (authority, root) = runtime.chain.current_liveness(&head).map_err(err)?;
        let receipt = link
            .receipt(
                &offer.id,
                0,
                offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16,
                0,
            )
            .map_err(err)?;
        let result = match offer.kind {
            ObjectKind::WorkProbeRequest => {
                pool.queue(
                    peer,
                    Decision::decode(bytes).map_err(err)?,
                    &authority,
                    root,
                    now_ms,
                )?;
                ProbeEvent::RequestQueued { receipt }
            }
            ObjectKind::WorkProbeFragment => {
                pool.signed(
                    None,
                    Proof::decode(bytes).map_err(err)?,
                    &authority,
                    root,
                    now_ms,
                )?;
                ProbeEvent::FragmentAccepted { receipt }
            }
            _ => unreachable!(),
        };
        // Never report an old-parent signature as current after verification.
        runtime.chain.current_liveness(&head).map_err(err)?;
        Ok(result)
    })();
    // Probe records are ephemeral. Completed malformed objects must not occupy
    // all eight durable reassembly slots forever; canonical data is unaffected.
    link.discard(&offer.id).map_err(err)?;
    result
}
