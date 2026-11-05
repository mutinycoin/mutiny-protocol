//! Internal authenticated parent projection. Canonical proof state and pending
//! recovery authority remain distinct; no recovery projection has a fake root.
use crate::{
    Error, Hash, Result, anchors::FinalizedAnchor, execution::State, recovery_history_v2::Book,
    recovery_transition_v2::Prepared,
};
#[derive(Clone, Copy)]
pub(crate) struct ParentContext<'a> {
    state: &'a State,
    parent: &'a FinalizedAnchor,
    root: Hash,
    history: &'a Book,
}
impl<'a> ParentContext<'a> {
    pub(crate) fn canonical(
        state: &'a State,
        parent: &'a FinalizedAnchor,
        root: Hash,
    ) -> Result<Self> {
        if state.root().map_err(|_| Error::WrongAnchor)? != root
            || (state.continuity.is_some() && state.accounting.slots.last_height != parent.height)
        {
            return Err(Error::WrongAnchor);
        }
        Ok(Self {
            state,
            parent,
            root,
            history: &state.recovery_history_v2,
        })
    }
    /// Prepared is unforgeable outside its full parent/material verifier. This
    /// remains tentative: only the canonical store can accept it durably.
    pub(crate) fn recovery(prepared: &'a Prepared) -> Self {
        Self {
            state: prepared.components(),
            parent: prepared.parent(),
            root: prepared.canonical_parent_root(),
            history: prepared.prospective_history(),
        }
    }
    pub(crate) fn state(self) -> &'a State {
        self.state
    }
    pub(crate) fn parent(self) -> &'a FinalizedAnchor {
        self.parent
    }
    pub(crate) fn root(self) -> Hash {
        self.root
    }
    pub(crate) fn history(self) -> &'a Book {
        self.history
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_only_context_never_becomes_height_or_voter_authority() {
        let policy_only = State::default();
        let parent = FinalizedAnchor {
            network: crate::NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: 59,
            block: [3; 32],
        };
        let root = policy_only.root().unwrap();
        let context = ParentContext::canonical(&policy_only, &parent, root).unwrap();
        assert!(
            crate::votes_v2::HeightAuthority::from_state(&policy_only, parent.clone(), root)
                .is_err()
        );
        let body = crate::blocks::BlockBody {
            height: 60,
            reward_owner: [0; 32],
            fees: 0,
            transactions: vec![],
            operations: vec![],
        };
        assert!(
            crate::continuity_lifecycle_v2::transition_in_parent(
                context,
                &body,
                &Default::default()
            )
            .is_err()
        );
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/bootstrap-recovery-replacement-public-v2.json"
        ))
        .unwrap();
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&f["root"]).try_into().unwrap();
        let rows: Vec<_> = f["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let state = State::from_records(&rows, root).unwrap();
        let mut parent = FinalizedAnchor::decode(&raw(&f["parent"])).unwrap();
        assert!(ParentContext::canonical(&state, &parent, root).is_ok());
        parent.height += 1;
        assert!(ParentContext::canonical(&state, &parent, root).is_err());
    }
}
