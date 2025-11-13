use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_consensus::simplex::signing_scheme::bls12381_multisig;
use commonware_cryptography::bls12381::primitives::variant::Variant;
use commonware_cryptography::ed25519::PublicKey;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::adb::store::{self, Store};
use commonware_storage::translator::TwoCap;
use commonware_utils::sequence::FixedBytes;
use summit_types::FinalizedHeader;
use summit_types::checkpoint::Checkpoint;
use summit_types::consensus_state::ConsensusState;

pub use store::Config;

// Key prefixes for different data types
const STATE_PREFIX: u8 = 0x01;
const CONSENSUS_STATE_PREFIX: u8 = 0x05;
const CHECKPOINT_PREFIX: u8 = 0x06;
const FINALIZED_HEADER_PREFIX: u8 = 0x07;

// State variable keys
const LATEST_CONSENSUS_STATE_HEIGHT_KEY: [u8; 2] = [STATE_PREFIX, 0];
const LATEST_FINALIZED_HEADER_HEIGHT_KEY: [u8; 2] = [STATE_PREFIX, 1];
const FINALIZED_CHECKPOINT_KEY: [u8; 2] = [CHECKPOINT_PREFIX, 1];

pub struct FinalizerState<E: Clock + Storage + Metrics, V: Variant> {
    store: Store<E, FixedBytes<64>, Value<V>, TwoCap>,
}

impl<E: Clock + Storage + Metrics, V: Variant> FinalizerState<E, V> {
    pub async fn new(context: E, cfg: Config<TwoCap, ()>) -> Self {
        let store = Store::<_, FixedBytes<64>, Value<V>, TwoCap>::init(context, cfg)
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

    fn make_finalized_header_key(height: u64) -> FixedBytes<64> {
        let mut key = [0u8; 64];
        key[0] = FINALIZED_HEADER_PREFIX;
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

    // FinalizedHeader height tracking operations
    async fn get_latest_finalized_header_height(&self) -> u64 {
        let key = Self::pad_key(&LATEST_FINALIZED_HEADER_HEIGHT_KEY);
        if let Some(Value::U64(height)) = self
            .store
            .get(&key)
            .await
            .expect("failed to get latest finalized header height")
        {
            height
        } else {
            0
        }
    }

    async fn set_latest_finalized_header_height(&mut self, height: u64) {
        let key = Self::pad_key(&LATEST_FINALIZED_HEADER_HEIGHT_KEY);
        self.store
            .update(key, Value::U64(height))
            .await
            .expect("failed to set latest finalized header height");
    }

    // ConsensusState blob operations
    pub async fn store_consensus_state(&mut self, height: u64, state: &ConsensusState) {
        let key = Self::make_consensus_state_key(height);
        self.store
            .update(key, Value::ConsensusState(Box::new(state.clone())))
            .await
            .expect("failed to store consensus state");

        // Update the latest height tracker
        let current_latest = self.get_latest_consensus_state_height().await;
        if height > current_latest {
            self.set_latest_consensus_state_height(height).await;
        }
    }

    pub async fn get_consensus_state(&self, height: u64) -> Option<ConsensusState> {
        let key = Self::make_consensus_state_key(height);
        if let Some(Value::ConsensusState(state)) = self
            .store
            .get(&key)
            .await
            .expect("failed to get consensus state")
        {
            Some(*state)
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

    // Checkpoint operations

    pub async fn store_finalized_checkpoint(&mut self, checkpoint: &Checkpoint) {
        let key = Self::pad_key(&FINALIZED_CHECKPOINT_KEY);
        self.store
            .update(key, Value::Checkpoint(checkpoint.clone()))
            .await
            .expect("failed to store finalized checkpoint");
    }

    #[allow(unused)]
    pub async fn get_finalized_checkpoint(&self) -> Option<Checkpoint> {
        let key = Self::pad_key(&FINALIZED_CHECKPOINT_KEY);
        if let Some(Value::Checkpoint(checkpoint)) = self
            .store
            .get(&key)
            .await
            .expect("failed to get finalized checkpoint")
        {
            Some(checkpoint)
        } else {
            None
        }
    }

    // FinalizedHeader operations
    pub async fn store_finalized_header(
        &mut self,
        height: u64,
        header: &FinalizedHeader<bls12381_multisig::Scheme<PublicKey, V>>,
    ) {
        let key = Self::make_finalized_header_key(height);
        self.store
            .update(key, Value::FinalizedHeader(Box::new(header.clone())))
            .await
            .expect("failed to store finalized header");

        // Update the latest finalized header height tracker
        let current_latest = self.get_latest_finalized_header_height().await;
        if height > current_latest {
            self.set_latest_finalized_header_height(height).await;
        }
    }

    #[allow(unused)]
    pub async fn get_finalized_header(
        &self,
        height: u64,
    ) -> Option<FinalizedHeader<bls12381_multisig::Scheme<PublicKey, V>>> {
        let key = Self::make_finalized_header_key(height);
        if let Some(Value::FinalizedHeader(header)) = self
            .store
            .get(&key)
            .await
            .expect("failed to get finalized header")
        {
            Some(*header)
        } else {
            None
        }
    }

    pub async fn get_most_recent_finalized_header(
        &self,
    ) -> Option<FinalizedHeader<bls12381_multisig::Scheme<PublicKey, V>>> {
        let latest_height = self.get_latest_finalized_header_height().await;
        if latest_height > 0 {
            self.get_finalized_header(latest_height).await
        } else {
            None
        }
    }

    // Commit all pending changes to the database
    pub async fn commit(&mut self) {
        self.store
            .commit(None)
            .await
            .expect("failed to commit to database");
    }
}

#[derive(Clone)]
enum Value<V: Variant> {
    U64(u64),
    ConsensusState(Box<ConsensusState>),
    Checkpoint(Checkpoint),
    FinalizedHeader(Box<FinalizedHeader<bls12381_multisig::Scheme<PublicKey, V>>>),
}

impl<V: Variant> EncodeSize for Value<V> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::U64(_) => 8,
            Self::ConsensusState(state) => state.encode_size(),
            Self::Checkpoint(checkpoint) => checkpoint.encode_size(),
            Self::FinalizedHeader(header) => header.encode_size(),
        }
    }
}

impl<V: Variant> Read for Value<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let value_type = buf.get_u8();
        match value_type {
            0x01 => Ok(Self::U64(buf.get_u64())),
            0x05 => Ok(Self::ConsensusState(Box::new(ConsensusState::read_cfg(
                buf,
                &(),
            )?))),
            0x06 => Ok(Self::Checkpoint(Checkpoint::read_cfg(buf, &())?)),
            0x07 => Ok(Self::FinalizedHeader(Box::new(FinalizedHeader::<
                bls12381_multisig::Scheme<PublicKey, V>,
            >::read_cfg(
                buf, &()
            )?))),
            byte => Err(Error::InvalidVarint(byte as usize)),
        }
    }
}

impl<V: Variant> Write for Value<V> {
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
            Self::Checkpoint(checkpoint) => {
                buf.put_u8(0x06);
                checkpoint.write(buf);
            }
            Self::FinalizedHeader(header) => {
                buf.put_u8(0x07);
                header.write(buf);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::simplex::signing_scheme::bls12381_multisig::Certificate as BlsCertificate;
    use commonware_consensus::simplex::signing_scheme::utils::Signers;
    use commonware_consensus::simplex::types::{Finalization, Proposal};
    use commonware_consensus::types::Round;
    use commonware_cryptography::bls12381::primitives::{
        group::{Element, G2},
        variant::MinPk,
    };
    use commonware_runtime::buffer::PoolRef;
    use commonware_runtime::{Runner as _, deterministic::Runner};
    use commonware_utils::{NZU64, NZUsize};

    async fn create_test_db_with_context<E: Clock + Storage + Metrics, V: Variant>(
        partition: &str,
        context: E,
    ) -> FinalizerState<E, V> {
        let config = Config {
            log_partition: format!("{}-log", partition),
            log_write_buffer: NZUsize!(64 * 1024),
            log_compression: None,
            log_codec_config: (),
            log_items_per_section: NZU64!(4),
            translator: TwoCap,
            buffer_pool: PoolRef::new(NZUsize!(77), NZUsize!(9)),
        };
        FinalizerState::<E, V>::new(context, config).await
    }

    #[test]
    fn test_consensus_state_blob_operations() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(1);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db =
                create_test_db_with_context::<_, MinPk>("test_consensus_state", context).await;

            // Create a test consensus state
            let mut consensus_state = ConsensusState::default();
            consensus_state.set_latest_height(42);

            // Test that no state exists initially
            assert!(db.get_consensus_state(42).await.is_none());
            assert!(db.get_latest_consensus_state().await.is_none());

            // Store the consensus state
            db.store_consensus_state(42, &consensus_state).await;
            db.commit().await;

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
            let mut newer_state = ConsensusState::default();
            newer_state.set_latest_height(100);
            db.store_consensus_state(100, &newer_state).await;
            db.commit().await;

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

    #[test]
    fn test_finalized_header_operations() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(3);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db =
                create_test_db_with_context::<_, MinPk>("test_finalized_header", context).await;

            // Create a test header
            let header = summit_types::Header::compute_digest(
                [1u8; 32].into(),                    // parent
                100,                                 // height
                1234567890,                          // timestamp
                0,                                   // epoch
                1,                                   // view
                [2u8; 32].into(),                    // payload_hash
                [3u8; 32].into(),                    // execution_request_hash
                [4u8; 32].into(),                    // checkpoint_hash
                [5u8; 32].into(),                    // prev_epoch_header_hash
                alloy_primitives::U256::from(42u64), // block_value
                Vec::new(),                          // added_validators
                Vec::new(),                          // removed_validators
            );

            // Create finalization proof
            let proposal = Proposal {
                round: Round::new(header.epoch, header.view),
                parent: header.height,
                payload: header.digest,
            };
            let finalized = Finalization {
                proposal,
                certificate: BlsCertificate {
                    signers: Signers::from(3, [0, 1, 2]),
                    signature: G2::one(), // Use one/generator instead of zero/infinity
                },
            };
            let finalized_header = summit_types::FinalizedHeader::new(header.clone(), finalized, 3);

            // Test that no header exists initially
            assert!(db.get_finalized_header(100).await.is_none());

            // Store the finalized header at height 100
            db.store_finalized_header(100, &finalized_header).await;
            db.commit().await;

            // Retrieve the finalized header
            let retrieved = db.get_finalized_header(100).await;
            assert!(retrieved.is_some());
            let retrieved = retrieved.unwrap();
            assert_eq!(retrieved.header.height, header.height);
            assert_eq!(retrieved.header.digest, header.digest);
            assert_eq!(retrieved.header.timestamp, header.timestamp);

            // Test that non-existent header returns None
            assert!(db.get_finalized_header(200).await.is_none());

            // Store another header at different height
            let header2 = summit_types::Header::compute_digest(
                [5u8; 32].into(),                    // parent
                200,                                 // height
                1234567900,                          // timestamp
                0,                                   // epoch
                2,                                   // view
                [6u8; 32].into(),                    // payload_hash
                [7u8; 32].into(),                    // execution_request_hash
                [8u8; 32].into(),                    // checkpoint_hash
                [9u8; 32].into(),                    // prev_epoch_header_hash
                alloy_primitives::U256::from(84u64), // block_value
                Vec::new(),                          // added_validators
                Vec::new(),                          // removed_validators
            );
            let proposal2 = Proposal {
                round: Round::new(header2.epoch, header2.view),
                parent: header2.height,
                payload: header2.digest,
            };
            let finalized2 = Finalization {
                proposal: proposal2,
                certificate: BlsCertificate {
                    signers: Signers::from(3, [0, 1, 2]),
                    signature: G2::one(),
                },
            };
            let finalized_header2 =
                summit_types::FinalizedHeader::new(header2.clone(), finalized2, 3);
            db.store_finalized_header(200, &finalized_header2).await;
            db.commit().await;

            // Both headers should be accessible
            let h1 = db.get_finalized_header(100).await.unwrap();
            let h2 = db.get_finalized_header(200).await.unwrap();
            assert_eq!(h1.header.height, 100);
            assert_eq!(h2.header.height, 200);
            assert_ne!(h1.header.digest, h2.header.digest);

            // Test get_most_recent_finalized_header returns the latest header
            let most_recent = db.get_most_recent_finalized_header().await;
            assert!(most_recent.is_some());
            let most_recent = most_recent.unwrap();
            assert_eq!(most_recent.header.height, 200);
            assert_eq!(most_recent.header.digest, header2.digest);
        });
    }

    #[test]
    fn test_most_recent_finalized_header_operations() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(5);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db = create_test_db_with_context::<_, MinPk>(
                "test_most_recent_finalized_header",
                context,
            )
            .await;

            // Test that no most recent header exists initially
            assert!(db.get_most_recent_finalized_header().await.is_none());

            // Store headers out of order
            let header1 = summit_types::Header::compute_digest(
                [1u8; 32].into(),                    // parent
                100,                                 // height
                1234567890,                          // timestamp
                0,                                   // epoch
                1,                                   // view
                [2u8; 32].into(),                    // payload_hash
                [3u8; 32].into(),                    // execution_request_hash
                [4u8; 32].into(),                    // checkpoint_hash
                [5u8; 32].into(),                    // prev_epoch_header_hash
                alloy_primitives::U256::from(42u64), // block_value
                Vec::new(),                          // added_validators
                Vec::new(),                          // removed_validators
            );
            let proposal1 = Proposal {
                round: Round::new(header1.epoch, header1.view),
                parent: header1.height,
                payload: header1.digest,
            };

            let finalized1 = Finalization {
                proposal: proposal1,
                certificate: BlsCertificate {
                    signers: Signers::from(3, [0, 1, 2]),
                    signature: G2::one(),
                },
            };
            let finalized_header1 =
                summit_types::FinalizedHeader::new(header1.clone(), finalized1, 3);

            let header3 = summit_types::Header::compute_digest(
                [7u8; 32].into(),                     // parent
                300,                                  // height
                1234567920,                           // timestamp
                0,                                    // epoch
                3,                                    // view
                [8u8; 32].into(),                     // payload_hash
                [9u8; 32].into(),                     // execution_request_hash
                [10u8; 32].into(),                    // checkpoint_hash
                [11u8; 32].into(),                    // prev_epoch_header_hash
                alloy_primitives::U256::from(126u64), // block_value
                Vec::new(),                           // added_validators
                Vec::new(),                           // removed_validators
            );
            let proposal3 = Proposal {
                round: Round::new(header3.epoch, header3.view),
                parent: header3.height,
                payload: header3.digest,
            };

            let finalized3 = Finalization {
                proposal: proposal3,
                certificate: BlsCertificate {
                    signers: Signers::from(3, [0, 1, 2]),
                    signature: G2::one(),
                },
            };
            let finalized_header3 =
                summit_types::FinalizedHeader::new(header3.clone(), finalized3, 3);

            let header2 = summit_types::Header::compute_digest(
                [5u8; 32].into(),                    // parent
                200,                                 // height
                1234567900,                          // timestamp
                0,                                   // epoch
                2,                                   // view
                [6u8; 32].into(),                    // payload_hash
                [7u8; 32].into(),                    // execution_request_hash
                [8u8; 32].into(),                    // checkpoint_hash
                [9u8; 32].into(),                    // prev_epoch_header_hash
                alloy_primitives::U256::from(84u64), // block_value
                Vec::new(),                          // added_validators
                Vec::new(),                          // removed_validators
            );
            let proposal2 = Proposal {
                round: Round::new(header2.epoch, header2.view),
                parent: header2.height,
                payload: header2.digest,
            };

            let finalized2 = Finalization {
                proposal: proposal2,
                certificate: BlsCertificate {
                    signers: Signers::from(3, [0, 1, 2]),
                    signature: G2::one(),
                },
            };
            let finalized_header2 =
                summit_types::FinalizedHeader::new(header2.clone(), finalized2, 3);

            // Store headers in non-sequential order: 100, 300, 200
            db.store_finalized_header(100, &finalized_header1).await;
            db.commit().await;

            // Most recent should be height 100
            let most_recent = db.get_most_recent_finalized_header().await.unwrap();
            assert_eq!(most_recent.header.height, 100);
            assert_eq!(most_recent.header.digest, header1.digest);

            // Store height 300
            db.store_finalized_header(300, &finalized_header3).await;
            db.commit().await;

            // Most recent should now be height 300
            let most_recent = db.get_most_recent_finalized_header().await.unwrap();
            assert_eq!(most_recent.header.height, 300);
            assert_eq!(most_recent.header.digest, header3.digest);

            // Store height 200 (lower than current max)
            db.store_finalized_header(200, &finalized_header2).await;
            db.commit().await;

            // Most recent should still be height 300
            let most_recent = db.get_most_recent_finalized_header().await.unwrap();
            assert_eq!(most_recent.header.height, 300);
            assert_eq!(most_recent.header.digest, header3.digest);

            // Verify all headers are still individually accessible
            let h1 = db.get_finalized_header(100).await.unwrap();
            let h2 = db.get_finalized_header(200).await.unwrap();
            let h3 = db.get_finalized_header(300).await.unwrap();
            assert_eq!(h1.header.height, 100);
            assert_eq!(h2.header.height, 200);
            assert_eq!(h3.header.height, 300);
        });
    }

    #[test]
    fn test_checkpoint_operations() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(4);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db = create_test_db_with_context::<_, MinPk>("test_checkpoint", context).await;

            // Create test consensus states with different heights to ensure different digests
            let mut finalized_state1 = ConsensusState::default();
            finalized_state1.set_latest_height(100);

            let mut finalized_state2 = ConsensusState::default();
            finalized_state2.set_latest_height(200);

            // Create test checkpoints
            let finalized_checkpoint1 =
                summit_types::checkpoint::Checkpoint::new(&finalized_state1);
            let finalized_checkpoint2 =
                summit_types::checkpoint::Checkpoint::new(&finalized_state2);

            // Test that no finalized checkpoint exists initially
            assert!(db.get_finalized_checkpoint().await.is_none());

            // Store finalized checkpoint
            db.store_finalized_checkpoint(&finalized_checkpoint1).await;
            db.commit().await;

            // Retrieve finalized checkpoint
            let retrieved_finalized = db.get_finalized_checkpoint().await;
            assert!(retrieved_finalized.is_some());
            let retrieved_finalized = retrieved_finalized.unwrap();
            assert_eq!(retrieved_finalized.data, finalized_checkpoint1.data);
            assert_eq!(retrieved_finalized.digest, finalized_checkpoint1.digest);

            // Test overwriting finalized checkpoint
            db.store_finalized_checkpoint(&finalized_checkpoint2).await;
            db.commit().await;

            let updated_finalized = db.get_finalized_checkpoint().await.unwrap();
            assert_eq!(updated_finalized.digest, finalized_checkpoint2.digest);
            assert_ne!(updated_finalized.digest, finalized_checkpoint1.digest);
        });
    }
}
