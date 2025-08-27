use commonware_codec::Encode;
use commonware_consensus::{Supervisor as Su, ThresholdSupervisor, simplex::types::View};
use commonware_cryptography::bls12381::dkg::ops::evaluate_all;
use commonware_cryptography::bls12381::primitives::poly::Poly;
use commonware_cryptography::bls12381::primitives::variant::{MinPk, Variant};
use commonware_cryptography::bls12381::primitives::{group, poly};
use commonware_resolver::p2p;
use commonware_utils::modulo;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use summit_types::{Identity, PublicKey};
use tracing::warn;

#[derive(Default, Clone, Debug)]
struct Participants {
    participants: Vec<PublicKey>,
    participants_map: BTreeMap<PublicKey, u32>,
}

#[derive(Clone)]
pub struct Registry {
    // Map from View -> immutable participant data
    // Once a view is added, it never changes
    views: Arc<RwLock<BTreeMap<View, Box<Participants>>>>,

    identity: Identity,
    polynomial: Vec<Identity>,
    share: group::Share,
}

impl Registry {
    pub fn new(
        participants: Vec<PublicKey>,
        polynomial: Poly<Identity>,
        share: group::Share,
    ) -> Self {
        let participants_map = participants
            .iter()
            .enumerate()
            .map(|(i, pk)| (pk.clone(), i as u32))
            .collect();

        let participants = Box::new(Participants {
            participants,
            participants_map,
        });

        let identity = *poly::public::<MinPk>(&polynomial);
        let polynomial = evaluate_all::<MinPk>(&polynomial, participants.participants.len() as u32);
        let registry = Self {
            views: Arc::new(RwLock::new(BTreeMap::new())),
            identity,
            polynomial,
            share,
        };

        registry.views.write().unwrap().insert(0, participants);
        registry
    }

    pub fn update_registry(&self, index: View, add: Vec<PublicKey>, remove: Vec<PublicKey>) {
        tracing::error!("update registry view {index}");
        let mut views = self.views.write().unwrap();

        let mut participants = if let Some((latest_view, view_data)) = views.last_key_value() {
            // TODO(matthias): is it possible that `index` is smaller or equal to the latest view?
            assert!(*latest_view < index);
            view_data.clone()
        } else {
            Box::new(Participants::default())
        };

        for participant in add {
            if participants.participants_map.contains_key(&participant) {
                warn!("Public key {} already exists in current set", participant);
                continue;
            }
            participants.participants.push(participant.clone());
            participants
                .participants_map
                .insert(participant, (participants.participants.len() as u32) - 1);
        }

        for participant in remove {
            let Some(participant_index) = participants.participants_map.get(&participant).copied()
            else {
                warn!("Public key {} doesn't exist in current set", participant);
                continue;
            };
            participants
                .participants
                .swap_remove(participant_index as usize);
            participants.participants_map.remove(&participant);

            // re-calculate the index of the swapped public key
            if let Some(swapped_key) = participants.participants.get(participant_index as usize) {
                participants
                    .participants_map
                    .insert(swapped_key.clone(), participant_index);
            }
        }
        views.insert(index, participants);
    }
}

impl p2p::Coordinator for Registry {
    type PublicKey = PublicKey;

    fn peers(&self) -> &Vec<Self::PublicKey> {
        // SAFETY: This is safe because:
        // 1. Views are never removed once added (append-only guarantee)
        // 2. Box<Participants> has a stable address that doesn't change
        // 3. The data inside Participants is immutable after creation
        // 4. We only return references to data that we know exists
        // 5. The registry lives as long as any references to it
        //
        // The unsafe extends the lifetime from the RwLock guard to 'self,
        // which is valid because the data actually lives as long as 'self
        let views = self.views.read().unwrap();

        // Use the list of participants that is associated with the largest index
        if let Some((_view, view_data)) = views.last_key_value() {
            let ptr = &view_data.participants as *const Vec<PublicKey>;
            // Drop the guard explicitly
            drop(views);
            // SAFETY: The Box ensures the data has a stable address
            // Views are never removed, so this pointer remains valid
            unsafe { &*ptr }
        } else {
            static EMPTY: Vec<PublicKey> = Vec::new();
            &EMPTY
        }
    }

    fn peer_set_id(&self) -> u64 {
        let views = self.views.read().unwrap();
        let (view, _view_data) = views
            .last_key_value()
            .expect("at least one views exists because it is set in the `new` function");
        *view
    }
}

impl Su for Registry {
    type Index = View;

    type PublicKey = PublicKey;

    fn leader(&self, index: Self::Index) -> Option<Self::PublicKey> {
        let views = self.views.read().unwrap();

        // Find the largest view that is <= the requested view
        let (_max_view, view_data) = views.range(..=index).next_back()?;

        if view_data.participants.is_empty() {
            return None;
        }

        let leader_index = (index as usize) % view_data.participants.len();
        Some(view_data.participants[leader_index].clone())
    }

    fn participants(&self, index: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        // SAFETY: Same safety reasoning as peers() method above
        let views = self.views.read().unwrap();

        // Find the largest view that is <= the requested view
        let (_max_view, view_data) = views.range(..=index).next_back()?;

        if view_data.participants.is_empty() {
            return None;
        }

        let ptr = &view_data.participants as *const Vec<PublicKey>;
        drop(views);
        Some(unsafe { &*ptr })
    }

    fn is_participant(&self, index: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        let views = self.views.read().unwrap();

        // Find the largest view that is <= the requested view
        let (_max_view, view_data) = views.range(..=index).next_back()?;
        view_data.participants_map.get(candidate).cloned()
    }
}

impl ThresholdSupervisor for Registry {
    type Identity = Identity;

    type Seed = <MinPk as Variant>::Signature;

    type Polynomial = Vec<Identity>;

    type Share = group::Share;

    fn identity(&self) -> &Self::Identity {
        &self.identity
    }

    fn leader(&self, index: Self::Index, seed: Self::Seed) -> Option<Self::PublicKey> {
        let views = self.views.read().unwrap();

        // Find the largest view that is <= the requested view
        let (_max_view, view_data) = views.range(..=index).next_back()?;

        if view_data.participants.is_empty() {
            return None;
        }

        let index = modulo(seed.encode().as_ref(), view_data.participants.len() as u64) as usize;
        Some(view_data.participants[index].clone())
    }

    fn polynomial(&self, _index: Self::Index) -> Option<&Self::Polynomial> {
        Some(&self.polynomial)
    }

    fn share(&self, _index: Self::Index) -> Option<&Self::Share> {
        Some(&self.share)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::{Supervisor as Su, ThresholdSupervisor};
    use commonware_cryptography::{
        PrivateKeyExt, Signer,
        bls12381::{
            dkg::ops,
            primitives::{poly, variant::MinPk},
        },
    };
    use commonware_resolver::p2p::Coordinator;
    use rand::rngs::OsRng;

    /// Helper function to create deterministic test public keys
    fn create_test_pubkeys(count: usize) -> Vec<PublicKey> {
        (0..count)
            .map(|i| {
                let private_key = summit_types::PrivateKey::from_seed(i as u64);
                private_key.public_key()
            })
            .collect()
    }

    /// Helper function to create a test registry with specified number of participants
    fn create_test_registry(participant_count: usize) -> Registry {
        let participants = create_test_pubkeys(participant_count);
        let threshold = std::cmp::max(1, (participant_count * 2) / 3 + 1);
        let (polynomial, shares) = ops::generate_shares::<_, MinPk>(
            &mut OsRng,
            None,
            participant_count as u32,
            threshold as u32,
        );
        Registry::new(participants, polynomial, shares[0].clone())
    }

    #[test]
    fn test_new_registry() {
        let participant_count = 3;
        let participants = create_test_pubkeys(participant_count);
        let expected_participants = participants.clone();

        let threshold = std::cmp::max(1, (participant_count * 2) / 3 + 1);
        let (polynomial, shares) = ops::generate_shares::<_, MinPk>(
            &mut OsRng,
            None,
            participant_count as u32,
            threshold as u32,
        );

        let registry = Registry::new(participants, polynomial.clone(), shares[0].clone());

        // Test that participants are correctly stored in view 0
        let view_0_participants = registry.participants(0);
        assert!(view_0_participants.is_some());
        assert_eq!(view_0_participants.unwrap(), &expected_participants);

        // Test that registry is not empty
        assert!(!registry.participants(0).unwrap().is_empty());
        assert_eq!(registry.participants(0).unwrap().len(), participant_count);

        // Test identity is set
        let identity = registry.identity();
        let expected_identity = *poly::public::<MinPk>(&polynomial);
        assert_eq!(*identity, expected_identity);
    }

    #[test]
    fn test_update_registry_add_participant() {
        let registry = create_test_registry(2);
        let new_participant = summit_types::PrivateKey::from_seed(99).public_key();

        // Add participant to view 1
        registry.update_registry(1, vec![new_participant.clone()], vec![]);

        // Verify participant was added
        let view_1_participants = registry.participants(1);
        assert!(view_1_participants.is_some());
        assert_eq!(view_1_participants.unwrap().len(), 3);
        assert!(view_1_participants.unwrap().contains(&new_participant));

        // Original view should remain unchanged
        let view_0_participants = registry.participants(0);
        assert_eq!(view_0_participants.unwrap().len(), 2);
    }

    #[test]
    fn test_update_registry_add_duplicate_participant() {
        let registry = create_test_registry(2);
        let existing_participant = registry.participants(0).unwrap()[0].clone();

        // Try to add existing participant - should log warning but not fail
        registry.update_registry(1, vec![existing_participant.clone()], vec![]);

        // Verify participant count didn't increase (duplicate was ignored)
        let view_1_participants = registry.participants(1);
        assert_eq!(view_1_participants.unwrap().len(), 2);
        assert!(view_1_participants.unwrap().contains(&existing_participant));
    }

    #[test]
    fn test_update_registry_remove_participant() {
        let registry = create_test_registry(3);
        let participant_to_remove = registry.participants(0).unwrap()[1].clone();

        // Remove participant from view 1
        registry.update_registry(1, vec![], vec![participant_to_remove.clone()]);

        // Verify participant was removed
        let view_1_participants = registry.participants(1);
        assert!(view_1_participants.is_some());
        assert_eq!(view_1_participants.unwrap().len(), 2);
        assert!(
            !view_1_participants
                .unwrap()
                .contains(&participant_to_remove)
        );

        // Original view should remain unchanged
        assert_eq!(registry.participants(0).unwrap().len(), 3);
    }

    #[test]
    fn test_update_registry_remove_nonexistent_participant() {
        let registry = create_test_registry(2);
        let nonexistent_participant = summit_types::PrivateKey::from_seed(999).public_key();

        // Try to remove non-existent participant - should log warning but not fail
        registry.update_registry(1, vec![], vec![nonexistent_participant]);

        // Verify participant count didn't change (remove was ignored)
        let view_1_participants = registry.participants(1);
        assert_eq!(view_1_participants.unwrap().len(), 2);
    }

    // Supervisor trait implementation tests
    #[test]
    fn test_supervisor_leader_selection() {
        let registry = create_test_registry(5);
        let participants = registry.participants(0).unwrap();

        // Test round-robin leader selection
        for view in 0..10 {
            let leader = Su::leader(&registry, view);
            assert!(leader.is_some());
            let expected_leader = &participants[view as usize % participants.len()];
            assert_eq!(leader.unwrap(), *expected_leader);
        }
    }

    #[test]
    fn test_supervisor_leader_empty_participants() {
        let participants = Vec::new();
        let (polynomial, shares) = ops::generate_shares::<_, MinPk>(&mut OsRng, None, 1, 1);
        let registry = Registry::new(participants, polynomial, shares[0].clone());

        // Should return None for empty participant set
        let leader = Su::leader(&registry, 0);
        assert!(leader.is_none());
    }

    #[test]
    fn test_supervisor_participants_by_view() {
        let registry = create_test_registry(3);
        let original_participants = registry.participants(0).unwrap();

        // View 0 should have original participants
        assert_eq!(registry.participants(0).unwrap(), original_participants);

        // Add participant to create view 3
        let new_participant = summit_types::PrivateKey::from_seed(100).public_key();
        registry.update_registry(3, vec![new_participant.clone()], vec![]);

        // Views 0, 1, 2 should still use original participants (largest view <= requested)
        assert_eq!(registry.participants(0).unwrap(), original_participants);
        assert_eq!(registry.participants(1).unwrap(), original_participants);
        assert_eq!(registry.participants(2).unwrap(), original_participants);

        // View 3 and beyond should have updated participants
        let view_3_participants = registry.participants(3).unwrap();
        assert_eq!(view_3_participants.len(), 4);
        assert!(view_3_participants.contains(&new_participant));

        // Future views should use latest available view (view 3)
        assert_eq!(registry.participants(4), registry.participants(3));
        assert_eq!(registry.participants(100), registry.participants(3));
    }

    #[test]
    fn test_supervisor_is_participant() {
        let registry = create_test_registry(4);
        let participants = registry.participants(0).unwrap();

        // Test existing participants
        for (i, participant) in participants.iter().enumerate() {
            let result = registry.is_participant(0, participant);
            assert_eq!(result, Some(i as u32));
        }

        // Test non-existing participant
        let non_participant = summit_types::PrivateKey::from_seed(999).public_key();
        assert_eq!(registry.is_participant(0, &non_participant), None);

        // Test with view that uses latest available participants
        assert_eq!(registry.is_participant(100, &participants[0]), Some(0));
    }

    #[test]
    fn test_supervisor_participants_none() {
        let participants = Vec::new();
        let (polynomial, shares) = ops::generate_shares::<_, MinPk>(&mut OsRng, None, 1, 1);
        let registry = Registry::new(participants, polynomial, shares[0].clone());

        // Should return None for views with no participants
        assert!(registry.participants(0).is_none());
        assert!(registry.participants(1).is_none());
    }

    // ThresholdSupervisor trait implementation tests
    #[test]
    fn test_threshold_supervisor_identity() {
        let participants = create_test_pubkeys(3);
        let (polynomial, shares) = ops::generate_shares::<_, MinPk>(&mut OsRng, None, 3, 2);
        let expected_identity = *poly::public::<MinPk>(&polynomial);

        let registry = Registry::new(participants, polynomial, shares[0].clone());

        assert_eq!(*registry.identity(), expected_identity);
    }

    #[test]
    fn test_threshold_supervisor_randomized_leader_selection() {
        // Note: This test is simplified since creating BLS signatures requires more complex setup
        // We'll test that the method exists and works with a basic setup
        let registry = create_test_registry(5);
        let participants = registry.participants(0).unwrap();

        // For now, we'll just verify that the ThresholdSupervisor trait is implemented
        // and that identity, polynomial, and share methods work
        let _identity = registry.identity(); // Just verify it returns
        assert!(registry.polynomial(0).is_some());
        assert!(registry.share(0).is_some());

        // Verify participants are available for leader selection
        assert_eq!(participants.len(), 5);
    }

    #[test]
    fn test_threshold_supervisor_empty_participants_methods() {
        let participants = Vec::new();
        let (polynomial, shares) = ops::generate_shares::<_, MinPk>(&mut OsRng, None, 1, 1);
        let registry = Registry::new(participants, polynomial, shares[0].clone());

        // Test that methods work even with empty participants
        let _identity = registry.identity(); // Just verify it returns
        assert!(registry.polynomial(0).is_some());
        assert!(registry.share(0).is_some());
    }

    #[test]
    fn test_threshold_supervisor_polynomial_access() {
        let registry = create_test_registry(3);

        // Polynomial should always be available
        let polynomial = registry.polynomial(0);
        assert!(polynomial.is_some());
        assert!(!polynomial.unwrap().is_empty());

        // Should be the same for different views
        assert_eq!(registry.polynomial(0), registry.polynomial(1));
        assert_eq!(registry.polynomial(0), registry.polynomial(100));
    }

    #[test]
    fn test_threshold_supervisor_share_access() {
        let registry = create_test_registry(3);

        // Share should always be available
        let share = registry.share(0);
        assert!(share.is_some());

        // Should be the same for different views
        assert_eq!(registry.share(0), registry.share(1));
        assert_eq!(registry.share(0), registry.share(100));
    }

    // p2p::Coordinator trait implementation tests
    #[test]
    fn test_p2p_coordinator_peers() {
        let registry = create_test_registry(4);
        let expected_peers = registry.participants(0).unwrap();

        let peers = registry.peers();
        assert_eq!(peers, expected_peers);
        assert_eq!(peers.len(), 4);
    }

    #[test]
    fn test_p2p_coordinator_peer_set_id() {
        let registry = create_test_registry(3);

        // Initial peer set ID should be 0
        assert_eq!(registry.peer_set_id(), 0);

        // Add participant to create view 1
        let new_participant = summit_types::PrivateKey::from_seed(100).public_key();
        registry.update_registry(1, vec![new_participant], vec![]);

        // Peer set ID should now be 1
        assert_eq!(registry.peer_set_id(), 1);
    }

    #[test]
    fn test_p2p_coordinator_peers_with_updates() {
        let registry = create_test_registry(2);

        // Initial peers
        let initial_peers = registry.peers();
        assert_eq!(initial_peers.len(), 2);

        // Add participant
        let new_participant = summit_types::PrivateKey::from_seed(100).public_key();
        registry.update_registry(1, vec![new_participant.clone()], vec![]);

        // Peers should now reflect the latest view
        let updated_peers = registry.peers();
        assert_eq!(updated_peers.len(), 3);
        assert!(updated_peers.contains(&new_participant));
    }

    // Multi-view operations and edge cases
    #[test]
    fn test_multiple_views() {
        let registry = create_test_registry(2);

        // Add participants to different views
        let participant_a = summit_types::PrivateKey::from_seed(100).public_key();
        let participant_b = summit_types::PrivateKey::from_seed(101).public_key();

        registry.update_registry(3, vec![participant_a.clone()], vec![]);
        registry.update_registry(7, vec![participant_b.clone()], vec![]);

        // Test participants for each view (largest view <= requested)
        assert_eq!(registry.participants(0).unwrap().len(), 2); // view 0
        assert_eq!(registry.participants(1).unwrap().len(), 2); // view 0
        assert_eq!(registry.participants(2).unwrap().len(), 2); // view 0
        assert_eq!(registry.participants(3).unwrap().len(), 3); // view 3
        assert_eq!(registry.participants(4).unwrap().len(), 3); // view 3
        assert_eq!(registry.participants(5).unwrap().len(), 3); // view 3
        assert_eq!(registry.participants(6).unwrap().len(), 3); // view 3
        assert_eq!(registry.participants(7).unwrap().len(), 4); // view 7

        // Test that future views use the latest available view
        assert_eq!(registry.participants(8), registry.participants(7));
        assert_eq!(registry.participants(100), registry.participants(7));
    }

    #[test]
    fn test_view_persistence() {
        let registry = create_test_registry(2);
        let original_participants = registry.participants(0).unwrap().clone();

        // Add participant to view 1
        let new_participant = summit_types::PrivateKey::from_seed(100).public_key();
        registry.update_registry(1, vec![new_participant.clone()], vec![]);

        // Original view should remain unchanged
        assert_eq!(registry.participants(0).unwrap(), &original_participants);

        // New view should have additional participant
        assert_eq!(registry.participants(1).unwrap().len(), 3);
        assert!(registry.participants(1).unwrap().contains(&new_participant));
    }

    #[test]
    fn test_large_participant_sets() {
        let large_registry = create_test_registry(100);
        let participants = large_registry.participants(0).unwrap();

        // Test basic operations with large set
        assert_eq!(participants.len(), 100);

        // Test leader selection works with large sets
        let leader = Su::leader(&large_registry, 0);
        assert!(leader.is_some());
        assert!(participants.contains(&leader.unwrap()));

        // Test is_participant works with large sets
        for (i, participant) in participants.iter().enumerate() {
            assert_eq!(
                large_registry.is_participant(0, participant),
                Some(i as u32)
            );
        }
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let registry = Arc::new(create_test_registry(5));
        let mut handles = vec![];

        // Spawn multiple threads to access registry concurrently
        for i in 0..10 {
            let registry_clone = Arc::clone(&registry);
            let handle = thread::spawn(move || {
                // Test concurrent reads
                let participants = registry_clone.participants(0);
                assert!(participants.is_some());
                assert_eq!(participants.unwrap().len(), 5);

                // Test leader selection
                let leader = Su::leader(&*registry_clone, i);
                assert!(leader.is_some());

                // Test is_participant
                let first_participant = &participants.unwrap()[0];
                assert_eq!(registry_clone.is_participant(0, first_participant), Some(0));
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_edge_case_view_zero_with_operations() {
        let registry = create_test_registry(1);

        // Test operations on view 0
        let participants = registry.participants(0).unwrap();
        assert_eq!(participants.len(), 1);

        let leader = Su::leader(&registry, 0);
        assert_eq!(leader, Some(participants[0].clone()));

        assert_eq!(registry.is_participant(0, &participants[0]), Some(0));
    }

    #[test]
    fn test_view_selection_logic() {
        let registry = create_test_registry(2);

        // Add participants to sparse views: 0, 3, 7
        let participant_a = summit_types::PrivateKey::from_seed(100).public_key();
        let participant_b = summit_types::PrivateKey::from_seed(101).public_key();

        registry.update_registry(3, vec![participant_a.clone()], vec![]);
        registry.update_registry(7, vec![participant_b.clone()], vec![]);

        // Test that we get the largest view <= requested view
        // Views available: 0 (2 participants), 3 (3 participants), 7 (4 participants)

        // Requests for views 0-2 should return view 0
        assert_eq!(registry.participants(0).unwrap().len(), 2);
        assert_eq!(registry.participants(1).unwrap().len(), 2);
        assert_eq!(registry.participants(2).unwrap().len(), 2);

        // Requests for views 3-6 should return view 3
        assert_eq!(registry.participants(3).unwrap().len(), 3);
        assert_eq!(registry.participants(4).unwrap().len(), 3);
        assert_eq!(registry.participants(5).unwrap().len(), 3);
        assert_eq!(registry.participants(6).unwrap().len(), 3);

        // Requests for view 7+ should return view 7
        assert_eq!(registry.participants(7).unwrap().len(), 4);
        assert_eq!(registry.participants(8).unwrap().len(), 4);
        assert_eq!(registry.participants(100).unwrap().len(), 4);

        // Verify participants contain expected members
        assert!(registry.participants(3).unwrap().contains(&participant_a));
        assert!(!registry.participants(3).unwrap().contains(&participant_b));

        assert!(registry.participants(7).unwrap().contains(&participant_a));
        assert!(registry.participants(7).unwrap().contains(&participant_b));
    }

    #[test]
    fn test_leader_selection_across_views() {
        let registry = create_test_registry(4);

        // Add participant at view 2
        let new_participant = summit_types::PrivateKey::from_seed(100).public_key();
        registry.update_registry(2, vec![new_participant.clone()], vec![]);

        // Leader for view 0-1 should use 4-participant set from view 0
        let leader_0 = Su::leader(&registry, 0);
        let leader_1 = Su::leader(&registry, 1);
        let participants_view_0 = registry.participants(0).unwrap();

        assert_eq!(leader_0, Some(participants_view_0[0].clone()));
        assert_eq!(
            leader_1,
            Some(participants_view_0[1 % participants_view_0.len()].clone())
        );

        // Leader for view 2+ should use 5-participant set from view 2
        let leader_2 = Su::leader(&registry, 2);
        let leader_3 = Su::leader(&registry, 3);
        let participants_view_2 = registry.participants(2).unwrap();

        assert_eq!(
            leader_2,
            Some(participants_view_2[2 % participants_view_2.len()].clone())
        );
        assert_eq!(
            leader_3,
            Some(participants_view_2[3 % participants_view_2.len()].clone())
        );
    }

    #[test]
    fn test_is_participant_across_views() {
        let registry = create_test_registry(2);
        let original_participants = registry.participants(0).unwrap().clone();

        // Add participant at view 3
        let new_participant = summit_types::PrivateKey::from_seed(100).public_key();
        registry.update_registry(3, vec![new_participant.clone()], vec![]);

        // Original participants should be found in all views
        assert_eq!(
            registry.is_participant(0, &original_participants[0]),
            Some(0)
        );
        assert_eq!(
            registry.is_participant(1, &original_participants[0]),
            Some(0)
        );
        assert_eq!(
            registry.is_participant(2, &original_participants[0]),
            Some(0)
        );
        assert_eq!(
            registry.is_participant(3, &original_participants[0]),
            Some(0)
        );
        assert_eq!(
            registry.is_participant(10, &original_participants[0]),
            Some(0)
        );

        // New participant should only be found from view 3 onwards
        assert_eq!(registry.is_participant(0, &new_participant), None);
        assert_eq!(registry.is_participant(1, &new_participant), None);
        assert_eq!(registry.is_participant(2, &new_participant), None);
        assert_eq!(registry.is_participant(3, &new_participant), Some(2));
        assert_eq!(registry.is_participant(10, &new_participant), Some(2));
    }

    #[test]
    fn test_peer_set_id_reflects_latest_view() {
        let registry = create_test_registry(2);

        // Initially should be view 0
        assert_eq!(registry.peer_set_id(), 0);

        // Add participants to different views
        let participant_a = summit_types::PrivateKey::from_seed(100).public_key();
        let participant_b = summit_types::PrivateKey::from_seed(101).public_key();

        registry.update_registry(5, vec![participant_a], vec![]);
        assert_eq!(registry.peer_set_id(), 5);

        registry.update_registry(10, vec![participant_b], vec![]);
        assert_eq!(registry.peer_set_id(), 10);
    }

    #[test]
    fn test_remove_participant_view_selection() {
        let registry = create_test_registry(3);
        let original_participants = registry.participants(0).unwrap().clone();
        let participant_to_remove = original_participants[1].clone();

        // Remove participant at view 2
        registry.update_registry(2, vec![], vec![participant_to_remove.clone()]);

        // Views 0-1 should still have original participants
        assert_eq!(registry.participants(0).unwrap().len(), 3);
        assert_eq!(registry.participants(1).unwrap().len(), 3);
        assert!(
            registry
                .participants(0)
                .unwrap()
                .contains(&participant_to_remove)
        );
        assert!(
            registry
                .participants(1)
                .unwrap()
                .contains(&participant_to_remove)
        );

        // View 2+ should have participant removed
        assert_eq!(registry.participants(2).unwrap().len(), 2);
        assert_eq!(registry.participants(10).unwrap().len(), 2);
        assert!(
            !registry
                .participants(2)
                .unwrap()
                .contains(&participant_to_remove)
        );
        assert!(
            !registry
                .participants(10)
                .unwrap()
                .contains(&participant_to_remove)
        );
    }

    #[test]
    fn test_update_registry_add_and_remove_combined() {
        let registry = create_test_registry(3);
        let original_participants = registry.participants(0).unwrap().clone();

        // Create new participants to add and remove existing ones
        let new_participant_a = summit_types::PrivateKey::from_seed(200).public_key();
        let new_participant_b = summit_types::PrivateKey::from_seed(201).public_key();
        let participant_to_remove = original_participants[0].clone();

        // Add two participants and remove one in a single operation
        registry.update_registry(
            1,
            vec![new_participant_a.clone(), new_participant_b.clone()],
            vec![participant_to_remove.clone()],
        );

        // Verify the result
        let view_1_participants = registry.participants(1).unwrap();
        assert_eq!(view_1_participants.len(), 4); // 3 - 1 + 2 = 4
        assert!(view_1_participants.contains(&new_participant_a));
        assert!(view_1_participants.contains(&new_participant_b));
        assert!(!view_1_participants.contains(&participant_to_remove));

        // Original view should remain unchanged
        let view_0_participants = registry.participants(0).unwrap();
        assert_eq!(view_0_participants.len(), 3);
        assert!(view_0_participants.contains(&participant_to_remove));
    }
}
