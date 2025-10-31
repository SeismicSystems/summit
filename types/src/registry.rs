use crate::PublicKey;
use commonware_consensus::types::View;
use commonware_p2p::Manager;
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, RwLock};
use commonware_utils::set::Ordered;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};

#[derive(Default, Clone, Debug)]
struct Inner {
    sets: BTreeMap<View, Ordered<PublicKey>>,
    subscribers: Vec<UnboundedSender<(u64, Ordered<PublicKey>, Ordered<PublicKey>)>>,
}

#[derive(Clone, Debug)]
pub struct Registry {
    // Map from View -> immutable participant data
    // Once a view is added, it never changes
    inner: Arc<RwLock<Inner>>,
}

impl Registry {
    pub fn new(id: u64, participants: Vec<PublicKey>) -> Self {
        let mut sets = BTreeMap::new();
        sets.insert(id, Ordered::from(participants));
        let inner = Inner { sets, subscribers: vec![] };
        Self {
            inner: Arc::new(RwLock::new(inner)),
        }
    }

    pub fn update_registry(&self, id: u64, add: &[PublicKey], remove: &[PublicKey]) {
        let mut inner = self.inner.write().unwrap();

        // TODO(matthias): we should also consider enforcing that the previous id must exist,
        // and do something like inner.sets.get(id - 1)
        let (_last_id, old_set) = inner.sets.last_key_value().expect("registry was initialized with an id");

        let mut new_set = Vec::with_capacity((old_set.len() + add.len()).saturating_sub(remove.len()));
        let remove: HashSet<PublicKey> = HashSet::from_iter(remove.iter().cloned());
        for key in old_set {
            if !remove.contains(key) {
                new_set.push(key.clone());
            }
        }
        for key in add {
            new_set.push(key.clone());
        }

        let old_set = old_set.clone();
        inner.sets.insert(id, Ordered::from(new_set.clone()));

        // Notify all subscribers
        let notification = (id, old_set, Ordered::from(new_set));
        inner.subscribers.retain(|tx| {
            tx.unbounded_send(notification.clone()).is_ok()
        });

        // TODO(matthias): consider garbage collection for old IDs
    }
}

impl Manager for Registry {
    type PublicKey = PublicKey;

    type Peers = Vec<PublicKey>;
    fn update(&mut self, id: u64, peers: Self::Peers) -> impl Future<Output=()> + Send {
        let mut inner = self.inner.write().unwrap();

        // Since IDs are monotonically increasing, the old set is the last one in the map
        let old_set = inner.sets.last_key_value()
            .map(|(_, set)| set.clone())
            .unwrap_or_else(|| Ordered::from(Vec::new()));

        let new_set = Ordered::from(peers);
        inner.sets.insert(id, new_set.clone());

        // Notify all subscribers
        let notification = (id, old_set, new_set);
        inner.subscribers.retain(|tx| {
            tx.unbounded_send(notification.clone()).is_ok()
        });

        async {}
    }

    fn peer_set(&mut self, id: u64) -> impl Future<Output=Option<Ordered<Self::PublicKey>>> + Send {
        let inner = self.inner.write().unwrap();
        let set = inner.sets.get(&id).map(|s| s.clone());
        async move { set }
    }

    fn subscribe(&mut self) -> impl Future<Output=UnboundedReceiver<(u64, Ordered<Self::PublicKey>, Ordered<Self::PublicKey>)>> + Send {
        let (tx, rx) = futures::channel::mpsc::unbounded();
        let mut inner = self.inner.write().unwrap();
        inner.subscribers.push(tx);
        async move { rx }
    }
}

//impl p2p::Coordinator for Registry {
//    type PublicKey = PublicKey;
//
//    fn peers(&self) -> &Vec<Self::PublicKey> {
//        // SAFETY: This is safe because:
//        // 1. Views are never removed once added (append-only guarantee)
//        // 2. Box<Participants> has a stable address that doesn't change
//        // 3. The data inside Participants is immutable after creation
//        // 4. We only return references to data that we know exists
//        // 5. The registry lives as long as any references to it
//        //
//        // The unsafe extends the lifetime from the RwLock guard to 'self,
//        // which is valid because the data actually lives as long as 'self
//        let views = self.views.read().unwrap();
//
//        // Use the list of participants that is associated with the largest index
//        if let Some((_view, view_data)) = views.last_key_value() {
//            let ptr = &view_data.participants as *const Vec<PublicKey>;
//            // Drop the guard explicitly
//            drop(views);
//            // SAFETY: The Box ensures the data has a stable address
//            // Views are never removed, so this pointer remains valid
//            unsafe { &*ptr }
//        } else {
//            static EMPTY: Vec<PublicKey> = Vec::new();
//            &EMPTY
//        }
//    }
//
//    fn peer_set_id(&self) -> u64 {
//        let views = self.views.read().unwrap();
//        let (view, _view_data) = views
//            .last_key_value()
//            .expect("at least one views exists because it is set in the `new` function");
//        *view
//    }
//}

//impl Su for Registry {
//    type Index = View;
//
//    type PublicKey = PublicKey;
//
//    //fn leader(&self, index: Self::Index) -> Option<Self::PublicKey> {
//    //    let views = self.views.read().unwrap();
//
//    //    // Find the largest view that is <= the requested view
//    //    let (_max_view, view_data) = views.range(..=index).next_back()?;
//
//    //    if view_data.participants.is_empty() {
//    //        return None;
//    //    }
//
//    //    let leader_index = (index as usize) % view_data.participants.len();
//    //    Some(view_data.participants[leader_index].clone())
//    //}
//
//    fn participants(&self, index: Self::Index) -> Option<&Vec<Self::PublicKey>> {
//        // SAFETY: Same safety reasoning as peers() method above
//        let views = self.views.read().unwrap();
//
//        // Find the largest view that is <= the requested view
//        let (_max_view, view_data) = views.range(..=index).next_back()?;
//
//        if view_data.participants.is_empty() {
//            return None;
//        }
//
//        let ptr = &view_data.participants as *const Vec<PublicKey>;
//        drop(views);
//        Some(unsafe { &*ptr })
//    }
//
//    fn is_participant(&self, index: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
//        let views = self.views.read().unwrap();
//
//        // Find the largest view that is <= the requested view
//        let (_max_view, view_data) = views.range(..=index).next_back()?;
//        view_data.participants_map.get(candidate).cloned()
//    }
//}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{PrivateKeyExt, Signer};
    use commonware_runtime::{Runner as _, deterministic::Runner};

    /// Helper function to create deterministic test public keys
    fn create_test_pubkeys(count: usize) -> Vec<PublicKey> {
        (0..count)
            .map(|i| {
                let private_key = crate::PrivateKey::from_seed(i as u64);
                private_key.public_key()
            })
            .collect()
    }

    /// Helper function to create a test registry with specified number of participants
    fn create_test_registry(participant_count: usize) -> Registry {
        let participants = create_test_pubkeys(participant_count);
        Registry::new(0, participants)
    }

    #[test]
    fn test_new_registry() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(0);
        let executor = Runner::from(cfg);
        executor.start(|_context| async move {
            let participant_count = 3;
            let participants = create_test_pubkeys(participant_count);
            let expected_participants = Ordered::from(participants.clone());

            let mut registry = Registry::new(0, participants);

            // Test that participants are correctly stored in id 0
            let peer_set_0 = registry.peer_set(0).await.unwrap();
            assert_eq!(peer_set_0.len(), participant_count);
            assert_eq!(peer_set_0, expected_participants);
        });
    }

    #[test]
    fn test_update_registry_add_participant() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(0);
        let executor = Runner::from(cfg);
        executor.start(|_context| async move {
            let mut registry = create_test_registry(2);
            let new_participant = crate::PrivateKey::from_seed(99).public_key();

            // Add participant to id 1
            let add = vec![new_participant.clone()];
            let remove = vec![];
            registry.update_registry(1, &add, &remove);

            // Verify participant was added
            let set_1 = registry.peer_set(1).await.unwrap();
            assert_eq!(set_1.len(), 3);
            assert!(set_1.iter().any(|p| p == &new_participant));

            // Original set should remain unchanged
            let set_0 = registry.peer_set(0).await;
            assert_eq!(set_0.unwrap().len(), 2);
        });
    }

    #[test]
    fn test_update_registry_remove_participant() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(0);
        let executor = Runner::from(cfg);
        executor.start(|_context| async move {
            let mut registry = create_test_registry(3);

            let set_0 = registry.peer_set(0).await.unwrap();
            let participant_to_remove = set_0.iter().nth(1).unwrap().clone();

            // Remove participant from id 1
            let add = vec![];
            let remove = vec![participant_to_remove.clone()];
            registry.update_registry(1, &add, &remove);

            // Verify participant was removed
            let set_1 = registry.peer_set(1).await.unwrap();
            assert_eq!(set_1.len(), 2);
            assert!(!set_1.iter().any(|p| p == &participant_to_remove));

            // Original set should remain unchanged
            assert_eq!(set_0.len(), 3);
        });
    }

    #[test]
    fn test_subscribe() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(0);
        let executor = Runner::from(cfg);
        executor.start(|_context| async move {
            let mut registry = create_test_registry(2);

            // Subscribe to updates
            let _rx = registry.subscribe().await;

            // Verify subscription was registered
            let inner = registry.inner.read().unwrap();
            assert_eq!(inner.subscribers.len(), 1);
        });
    }

    #[test]
    fn test_subscribers_receive_updates() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(0);
        let executor = Runner::from(cfg);
        executor.start(|_context| async move {
            use futures::StreamExt;

            let mut registry = create_test_registry(2);

            // Subscribe to updates
            let mut rx = registry.subscribe().await;

            // Get the initial peer set
            let set_0 = registry.peer_set(0).await.unwrap();

            // Use the Manager trait's update method to trigger notifications
            let new_participant = crate::PrivateKey::from_seed(99).public_key();
            let mut new_peers = set_0.iter().cloned().collect::<Vec<_>>();
            new_peers.push(new_participant.clone());

            registry.update(1, new_peers.clone()).await;

            // Verify the update was applied
            let set_1 = registry.peer_set(1).await.unwrap();
            assert_eq!(set_1.len(), 3);
            assert!(set_1.iter().any(|p| p == &new_participant));

            // Verify subscribers received the notification
            let notification = rx.next().await;
            assert!(notification.is_some());

            let (id, old_set, new_set) = notification.unwrap();
            assert_eq!(id, 1);
            assert_eq!(old_set, set_0);
            assert_eq!(new_set, set_1);
        });
    }
}

