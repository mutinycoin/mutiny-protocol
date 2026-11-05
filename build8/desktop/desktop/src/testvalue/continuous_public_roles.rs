//! SOURCE PROPOSAL ONLY. Fixed PUBLIC TEST-VALUE roles; nonshipping roots only.
//! These words/entropy are deliberately public fixtures, never user custody input.
use crate::wallet_v2::{RestoredKey, Session};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicRole { Ordinary, Buyer, Treasury }
impl PublicRole {
    pub fn initial_phrase(self) -> String {
        match self {
            Self::Ordinary => format!("{}art", "abandon ".repeat(23)),
            Self::Buyer => "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title".into(),
            Self::Treasury => format!("{}vote", "zoo ".repeat(23)),
        }
    }
    pub fn rotation_phrase(self) -> &'static str {
        match self {
            Self::Ordinary => "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            Self::Buyer => "category cancel animal embark drastic bamboo mountain loyal category cancel animal embark drastic bamboo mountain loyal category cancel animal embark drastic bamboo mountain myself",
            Self::Treasury => "drastic bamboo mountain loyal category cancel animal embark drastic bamboo mountain loyal category cancel animal embark drastic bamboo mountain loyal category cancel animal embark",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn fixed_public_roles_have_distinct_gen2_destinations_and_keep_exact_authority() {
        let mut addresses = BTreeSet::new();
        let mut restored_keys = Vec::new();
        for role in [PublicRole::Ordinary, PublicRole::Buyer, PublicRole::Treasury] {
            let initial = Session::restore_initial(&role.initial_phrase()).unwrap();
            assert!(addresses.insert(initial.identity().address_id.clone()));
            let authority = hex::decode(&initial.identity().authority_id).unwrap().try_into().unwrap();
            let restored = RestoredKey::restore(role.rotation_phrase(), 2, None).unwrap();
            let descriptor = restored.descriptor().to_vec();
            let repeated = RestoredKey::restore(role.rotation_phrase(), 2, Some(&descriptor)).unwrap();
            assert_eq!(restored.fingerprint(), repeated.fingerprint());
            let rotated = Session::restore_rotated(restored, authority, &descriptor).unwrap();
            assert_eq!(rotated.identity().authority_id, initial.identity().authority_id);
            assert_eq!(rotated.identity().generation, 2);
            assert!(addresses.insert(rotated.identity().address_id.clone()), "public role collision {role:?}");
            restored_keys.push((role, descriptor));
        }
        assert_eq!(addresses.len(), 6);
        for (role, descriptor) in &restored_keys {
            for (other, wrong) in &restored_keys {
                if role != other {
                    assert_ne!(descriptor, wrong);
                    assert!(RestoredKey::restore(role.rotation_phrase(), 2, Some(wrong)).is_err());
                }
            }
        }
    }
}
