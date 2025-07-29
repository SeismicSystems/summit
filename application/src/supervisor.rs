use commonware_codec::Encode;
use commonware_consensus::{Supervisor as Su, ThresholdSupervisor, threshold_simplex::types::View};
use commonware_cryptography::{
    bls12381::{
        dkg::ops::evaluate_all,
        primitives::{
            group,
            poly::{self, Poly},
            variant::{MinPk, Variant},
        },
    },
    ed25519::PublicKey,
};
use commonware_utils::modulo;
use std::collections::HashMap;
use summit_types::Identity;
#[derive(Clone)]
pub struct Supervisor {
    identity: Identity,
    polynomial: Vec<Identity>,
    participants: Vec<PublicKey>,
    participants_map: HashMap<PublicKey, u32>,

    share: group::Share,
}

impl Supervisor {
    pub fn new(
        participants: Vec<PublicKey>,
        polynomial: Poly<Identity>,
        share: group::Share,
    ) -> Self {
        // Setup participants
        //  participants.sort();
        let mut participants_map = HashMap::with_capacity(participants.len());
        for (index, validator) in participants.iter().enumerate() {
            participants_map.insert(validator.clone(), index as u32);
        }

        let identity = *poly::public::<MinPk>(&polynomial);

        let polynomial = evaluate_all::<MinPk>(&polynomial, participants.len() as u32);
        // Return supervisor
        Self {
            identity,
            polynomial,
            participants,
            participants_map,
            share,
        }
    }
}

impl Su for Supervisor {
    type Index = View;

    type PublicKey = PublicKey;

    fn leader(&self, _index: Self::Index) -> Option<Self::PublicKey> {
        unimplemented!("only defined in supertrait")
    }

    fn participants(&self, _index: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        Some(&self.participants)
    }

    fn is_participant(&self, _index: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.participants_map.get(candidate).cloned()
    }
}

impl ThresholdSupervisor for Supervisor {
    type Identity = Identity;

    type Seed = <MinPk as Variant>::Signature;

    type Polynomial = Vec<Identity>;

    type Share = group::Share;

    fn identity(&self) -> &Self::Identity {
        &self.identity
    }

    fn leader(&self, _index: Self::Index, seed: Self::Seed) -> Option<Self::PublicKey> {
        let index = modulo(seed.encode().as_ref(), self.participants.len() as u64) as usize;
        Some(self.participants[index].clone())
    }

    fn polynomial(&self, _index: Self::Index) -> Option<&Self::Polynomial> {
        Some(&self.polynomial)
    }

    fn share(&self, _index: Self::Index) -> Option<&Self::Share> {
        Some(&self.share)
    }
}
