use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::store::{self, Store};
use commonware_storage::translator::TwoCap;
use commonware_utils::sequence::FixedBytes;
pub use store::Config;
use summit_types::consensus_state::ConsensusState;

// Key prefixes for different data types
const STATE_PREFIX: u8 = 0x01;
const CONSENSUS_STATE_PREFIX: u8 = 0x05;

// State variable keys
const LATEST_CONSENSUS_STATE_HEIGHT_KEY: [u8; 2] = [STATE_PREFIX, 0];

pub struct FinalizerState<E: Clock + Storage + Metrics> {
    store: Store<E, FixedBytes<64>, Value, TwoCap>,
}

impl<E: Clock + Storage + Metrics> FinalizerState<E> {
    pub async fn new(context: E, cfg: Config<TwoCap, ()>) -> Self {
        let store = Store::<_, FixedBytes<64>, Value, TwoCap>::init(context, cfg)
            .await
            .expect("failed to initialize unified store");

        Self { store }
    }

    fn pad_key(key: &[u8]) -> FixedBytes<64> {
        let mut padded = [0u8; 64];
        let len = key.len().min(64);
        padded[..len].copy_from_slice(&key[..len]);
        FixedBytes::new(padded)
    }

    fn make_consensus_state_key(height: u64) -> FixedBytes<64> {
        let mut key = [0u8; 64];
        key[0] = CONSENSUS_STATE_PREFIX;
        key[1..9].copy_from_slice(&height.to_be_bytes());
        FixedBytes::new(key)
    }

    // State variable operations
    async fn get_latest_consensus_state_height(&self) -> u64 {
        let key = Self::pad_key(&LATEST_CONSENSUS_STATE_HEIGHT_KEY);
        if let Some(Value::U64(height)) = self
            .store
            .get(&key)
            .await
            .expect("failed to get latest consensus state height")
        {
            height
        } else {
            0
        }
    }

    async fn set_latest_consensus_state_height(&mut self, height: u64) {
        let key = Self::pad_key(&LATEST_CONSENSUS_STATE_HEIGHT_KEY);
        self.store
            .update(key, Value::U64(height))
            .await
            .expect("failed to set latest consensus state height");
    }

    // ConsensusState blob operations
    pub async fn store_consensus_state(&mut self, height: u64, state: &ConsensusState) {
        let key = Self::make_consensus_state_key(height);
        self.store
            .update(key, Value::ConsensusState(state.clone()))
            .await
            .expect("failed to store consensus state");

        // Update the latest height tracker
        let current_latest = self.get_latest_consensus_state_height().await;
        if height > current_latest {
            self.set_latest_consensus_state_height(height).await;
        }

        self.store
            .commit()
            .await
            .expect("failed to commit consensus state");
    }

    pub async fn get_consensus_state(&self, height: u64) -> Option<ConsensusState> {
        let key = Self::make_consensus_state_key(height);
        if let Some(Value::ConsensusState(state)) = self
            .store
            .get(&key)
            .await
            .expect("failed to get consensus state")
        {
            Some(state)
        } else {
            None
        }
    }

    pub async fn get_latest_consensus_state(&self) -> Option<ConsensusState> {
        // Check if we have a latest height tracker
        let key = Self::pad_key(&LATEST_CONSENSUS_STATE_HEIGHT_KEY);
        if let Some(Value::U64(latest_height)) = self
            .store
            .get(&key)
            .await
            .expect("failed to get latest consensus state height")
        {
            self.get_consensus_state(latest_height).await
        } else {
            None
        }
    }
}

#[derive(Clone)]
enum Value {
    U64(u64),
    ConsensusState(ConsensusState),
}

impl EncodeSize for Value {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::U64(_) => 8,
            Self::ConsensusState(state) => state.encode_size(),
        }
    }
}

impl Read for Value {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let value_type = buf.get_u8();
        match value_type {
            0x01 => Ok(Self::U64(buf.get_u64())),
            0x05 => Ok(Self::ConsensusState(ConsensusState::read_cfg(buf, &())?)),
            byte => Err(Error::InvalidVarint(byte as usize)),
        }
    }
}

impl Write for Value {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::U64(val) => {
                buf.put_u8(0x01);
                buf.put_u64(*val);
            }
            Self::ConsensusState(state) => {
                buf.put_u8(0x05);
                state.write(buf);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::buffer::PoolRef;
    use commonware_runtime::{Runner as _, deterministic::Runner};
    use commonware_utils::{NZU64, NZUsize};

    async fn create_test_db_with_context<E: Clock + Storage + Metrics>(
        partition: &str,
        context: E,
    ) -> FinalizerState<E> {
        let config = Config {
            log_journal_partition: format!("{}-log", partition),
            log_write_buffer: NZUsize!(64 * 1024),
            log_compression: None,
            log_codec_config: (),
            log_items_per_section: NZU64!(4),
            locations_journal_partition: format!("{}-locations", partition),
            locations_items_per_blob: NZU64!(4),
            translator: TwoCap,
            buffer_pool: PoolRef::new(NZUsize!(77), NZUsize!(9)),
        };
        FinalizerState::new(context, config).await
    }

    #[test]
    fn test_consensus_state_blob_operations() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(1);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db = create_test_db_with_context("test_consensus_state", context).await;

            // Create a test consensus state
            let mut consensus_state = ConsensusState::new();
            consensus_state.set_latest_height(42);

            // Test that no state exists initially
            assert!(db.get_consensus_state(42).await.is_none());
            assert!(db.get_latest_consensus_state().await.is_none());

            // Store the consensus state
            db.store_consensus_state(42, &consensus_state).await;

            // Retrieve the consensus state
            let retrieved = db.get_consensus_state(42).await;
            assert!(retrieved.is_some());
            let retrieved = retrieved.unwrap();
            assert_eq!(retrieved.get_latest_height(), 42);

            // Test get_latest_consensus_state
            let latest = db.get_latest_consensus_state().await;
            assert!(latest.is_some());
            let latest = latest.unwrap();
            assert_eq!(latest.get_latest_height(), 42);

            // Store a newer state
            let mut newer_state = ConsensusState::new();
            newer_state.set_latest_height(100);
            db.store_consensus_state(100, &newer_state).await;

            // Should return the most recent state
            let latest = db.get_latest_consensus_state().await;
            assert!(latest.is_some());
            let latest = latest.unwrap();
            assert_eq!(latest.get_latest_height(), 100);

            // Old state should still be accessible
            let old_state = db.get_consensus_state(42).await;
            assert!(old_state.is_some());
            assert_eq!(old_state.unwrap().get_latest_height(), 42);
        });
    }
}
