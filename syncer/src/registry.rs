use summit_types::PublicKey;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use commonware_resolver::p2p;
use commonware_consensus::{Supervisor as Su, simplex::types::View};
use std::sync::atomic::{AtomicU64, Ordering};
use anyhow::Result;

#[derive(Default, Clone)]
struct Participants {
    participants: Vec<PublicKey>,
    participants_map: HashMap<PublicKey, u32>,
}

#[derive(Clone)]
pub struct Registry {
    // Map from View -> immutable participant data
    // Once a view is added, it never changes
    views: Arc<RwLock<HashMap<View, Box<Participants>>>>,

    // Track the latest/highest view number
    latest_view: Arc<AtomicU64>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            views: Arc::new(RwLock::new(HashMap::new())),
            latest_view: Arc::new(AtomicU64::new(1)),
        }
    }
}


impl Registry {
    pub fn new(participants: Vec<PublicKey>) -> Self {
        let participants_map = participants
            .iter()
            .enumerate()
            .map(|(i, pk)| (pk.clone(), i as u32))
            .collect();

        let participants = Box::new(Participants {
            participants,
            participants_map,
        });

        let registry = Self::default();
        let view = registry.latest_view.load(Ordering::Relaxed);
        registry.views.write().unwrap().insert(view, participants);
        registry
    }

    pub fn add_participant(&self, participant: PublicKey) -> Result<()> {
        let mut views = self.views.write().unwrap();
        let current_latest = self.latest_view.load(Ordering::Relaxed);

        let mut participants = views.get(&current_latest).map(|x| x.as_ref().clone()).unwrap_or_default();

        if participants.participants_map.contains_key(&participant) {
            return Err(anyhow::anyhow!("Public key {} already exists in current set", participant));
        }

        participants.participants.push(participant.clone());
        participants.participants_map.insert(participant, (participants.participants.len() as u32) - 1);

        self.latest_view.store(current_latest + 1, Ordering::Relaxed);
        views.insert(current_latest + 1, Box::new(participants));
        Ok(())
    }

    pub fn remove_participant(&mut self, participant: PublicKey) -> Result<()> {
        let mut views = self.views.write().unwrap();
        let current_latest = self.latest_view.load(Ordering::Relaxed);

        let mut participants = views.get(&current_latest).map(|x| x.as_ref().clone()).unwrap_or_default();

        let Some(index) = participants.participants_map.get(&participant).map(|x| *x) else {
            return Err(anyhow::anyhow!("Public key {} doesn't exist in current set", participant));
        };

        participants.participants.swap_remove(index as usize);
        participants.participants_map.remove(&participant);

        // re-calculate the index of the swapped public key
        if let Some(swapped_key) = participants.participants.get(index as usize) {
            participants.participants_map.insert(swapped_key.clone(), index);
        }

        self.latest_view.store(current_latest + 1, Ordering::Relaxed);
        views.insert(current_latest + 1, Box::new(participants));
        Ok(())
    }
}


impl p2p::Coordinator for Registry {
    type PublicKey = PublicKey;

    fn peers(&self) -> &Vec<Self::PublicKey> {
        let latest = self.latest_view.load(std::sync::atomic::Ordering::Relaxed);

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
        if let Some(view_data) = views.get(&latest) {
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
        self.latest_view.load(Ordering::Relaxed)
    }
}


impl Su for Registry {
    type Index = View;

    type PublicKey = PublicKey;

    fn leader(&self, index: Self::Index) -> Option<Self::PublicKey> {
        let current_latest = self.latest_view.load(Ordering::Relaxed);
        let views = self.views.read().unwrap();
        let view_data = views.get(&current_latest)?;

        if view_data.participants.is_empty() {
            return None;
        }

        let leader_index = (index as usize) % view_data.participants.len();
        Some(view_data.participants[leader_index].clone())
    }

    fn participants(&self, _index: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        // SAFETY: Same safety reasoning as peers() method above
        let current_latest = self.latest_view.load(Ordering::Relaxed);
        let views = self.views.read().unwrap();
        if let Some(view_data) = views.get(&current_latest) {
            let ptr = &view_data.participants as *const Vec<PublicKey>;
            drop(views);
            Some(unsafe { &*ptr })
        } else {
            None
        }
    }

    fn is_participant(&self, _index: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        let current_latest = self.latest_view.load(Ordering::Relaxed);
        let views = self.views.read().unwrap();
        let participants = views.get(&current_latest)?;
        participants.participants_map.get(candidate).cloned()
    }
}

