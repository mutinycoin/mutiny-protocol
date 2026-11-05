//! Bounded bidirectional exchange over one authenticated outbound connection.
//! Socket work never owns the actor lock. Each ingress executes its ordinary
//! validation; transport direction does not grant additional authority.
use crate::{
    peer_client::PeerClient,
    peer_server::PeerBackend,
    peer_sync::{catch_up, local, push_history},
};
use mutiny_consensus_v8::Hash;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
type Result<T> = std::result::Result<T, String>;
#[derive(Default)]
struct PageCursor {
    operations: u64,
    candidates: u64,
    votes: u64,
}
#[derive(Default)]
pub struct GossipCursor {
    height: u64,
    pull: PageCursor,
    push: PageCursor,
}
#[derive(Default, Debug)]
pub struct Exchange {
    pub finalized: usize,
    pub candidates: usize,
    pub votes: usize,
    pub operations: usize,
    pub proposal: bool,
}
pub fn exchange<B: PeerBackend>(
    client: &mut PeerClient,
    actor: &Arc<Mutex<B>>,
    peer: Hash,
    cursor: &mut GossipCursor,
) -> Result<Exchange> {
    let pull = catch_up(client, actor, peer, 8)?;
    let mut result = Exchange {
        finalized: pull.accepted,
        ..Exchange::default()
    };
    if pull.local_height < pull.advertised_height {
        return Ok(result);
    }
    let push = push_history(client, actor, peer, 8)?;
    result.finalized += push.accepted;
    if push.local_height != push.advertised_height {
        return Ok(result);
    }
    let target = push.local_height.checked_add(1).ok_or("Height exhausted")?;
    if cursor.height != target {
        *cursor = GossipCursor {
            height: target,
            ..GossipCursor::default()
        };
    }
    let mut remote = |method: &str, args: Value| {
        client.request(method, args.as_object().ok_or("Request fields")?)
    };
    let mut own = |method: &str, args: Value| local(actor, peer, method, args);
    transfer(&mut remote, &mut own, target, &mut cursor.pull, &mut result)?;
    transfer(&mut own, &mut remote, target, &mut cursor.push, &mut result)?;
    // Either coordinator can ask the other side for a work lease. Responses
    // may become available on a later tick and are retried by identity.
    probe(&mut own, &mut remote)?;
    probe(&mut remote, &mut own)?;
    Ok(result)
}
type Endpoint<'a> = dyn FnMut(&str, Value) -> Result<Value> + 'a;
fn transfer(
    source: &mut Endpoint<'_>,
    destination: &mut Endpoint<'_>,
    height: u64,
    cursor: &mut PageCursor,
    result: &mut Exchange,
) -> Result<()> {
    for (get, submit, field, offset, maximum, total, count) in [
        (
            "get_operations",
            "submit_operation",
            "operation",
            &mut cursor.operations,
            16,
            4096,
            &mut result.operations,
        ),
        (
            "get_candidates",
            "submit_candidate",
            "candidate",
            &mut cursor.candidates,
            4,
            1024,
            &mut result.candidates,
        ),
        (
            "get_votes",
            "submit_vote",
            "vote",
            &mut cursor.votes,
            128,
            100000,
            &mut result.votes,
        ),
    ] {
        let page = source(get, json!({"height":height,"offset":*offset}))?;
        let (items, next) = page_items(&page, *offset, maximum, total)?;
        for item in items {
            destination(submit, json!({field:item}))?;
            *count += 1;
        }
        *offset = next;
    }
    let answer = source("get_round_proposal", json!({}))?;
    let status = destination("status", json!({}))?;
    if status["voting_enabled"] == true {
        if let Some(raw) = answer["proposal"].as_str() {
            if raw.len() > 2 * crate::round_proposal::MAX_WIRE {
                return Err("Proposal gossip bound".into());
            }
            let proposal = crate::round_proposal::RoundProposal::decode(
                &hex::decode(raw).map_err(|e| e.to_string())?,
            )?;
            if proposal.parent.height.checked_add(1) == Some(height) {
                destination("submit_round_proposal", json!({"proposal":raw}))?;
                result.proposal = true;
            }
        }
    }
    Ok(())
}
fn probe(requester: &mut Endpoint<'_>, responder: &mut Endpoint<'_>) -> Result<()> {
    let own = requester("get_work_probe", json!({}))?;
    if let Some(probe) = own["probe"].as_str() {
        responder("queue_work_probe", json!({"probe":probe}))?;
        let response = responder("get_work_response", json!({}))?;
        if let Some(fragment) = response["fragment"].as_str() {
            requester("submit_work_fragment", json!({"fragment":fragment}))?;
        }
    }
    Ok(())
}
fn page_items(page: &Value, offset: u64, maximum: usize, total: u64) -> Result<(&Vec<Value>, u64)> {
    let items = page["items"].as_array().ok_or("Gossip items")?;
    if items.len() > maximum || items.iter().any(|v| !v.is_string()) {
        return Err("Gossip item bound/type".into());
    }
    let next = offset
        .checked_add(items.len() as u64)
        .ok_or("Cursor overflow")?;
    if next > total || page["next"].as_u64() != Some(next) {
        return Err("Gossip cursor mismatch".into());
    }
    let complete = page["complete"].as_bool().ok_or("Gossip completion flag")?;
    if !complete && items.is_empty() {
        return Err("Nonadvancing gossip cursor".into());
    }
    Ok((items, if complete { 0 } else { next }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_pagination_rejects_peer_cursor_manipulation() {
        assert_eq!(
            page_items(
                &json!({"items":["00"],"next":4,"complete":false}),
                3,
                4,
                1024
            )
            .unwrap()
            .1,
            4
        );
        assert_eq!(
            page_items(&json!({"items":[],"next":4,"complete":true}), 4, 4, 1024)
                .unwrap()
                .1,
            0
        );
        for bad in [
            json!({"items":["00"],"next":999,"complete":false}),
            json!({"items":[],"next":4,"complete":false}),
            json!({"items":[1],"next":5,"complete":true}),
        ] {
            assert!(page_items(&bad, 4, 4, 1024).is_err());
        }
    }
}
