use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_consensus::simplex::scheme::bls12381_multisig;
use commonware_cryptography::bls12381::primitives::variant::Variant;
use commonware_cryptography::ed25519::PublicKey;
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use commonware_storage::qmdb::store::db::{self, Db};
use commonware_storage::translator::EightCap;
use commonware_utils::sequence::FixedBytes;
use summit_types::checkpoint::Checkpoint;
use summit_types::consensus_state::ConsensusState;
use summit_types::{Block, FinalizedHeader};
use tokio_util::sync::CancellationToken;
use tracing::error;

pub use db::Config;

/// Shared by startup recovery (before P2P allocation) and the finalizer actor.
pub fn config(
    prefix: &str,
    page_cache: commonware_runtime::buffer::paged::CacheRef,
) -> Config<EightCap, ((), ())> {
    Config {
        log: commonware_storage::journal::contiguous::variable::Config {
            partition: format!("{prefix}-finalizer_state-log"),
            write_buffer: commonware_utils::NZUsize!(1024 * 1024),
            replay_buffer: commonware_utils::NZUsize!(1024 * 1024),
            compression: None,
            codec_config: ((), ()),
            items_per_section: commonware_utils::NZU64!(262_144),
            page_cache,
        },
        translator: EightCap,
        init_cache_size: Some(commonware_utils::NZUsize!(1024)),
        init_buffer: commonware_utils::NZUsize!(1024 * 1024),
    }
}

// Key prefixes for different data types
const STATE_PREFIX: u8 = 0x01;
const CONSENSUS_STATE_PREFIX: u8 = 0x05;
const CHECKPOINT_PREFIX: u8 = 0x06;
const FINALIZED_HEADER_PREFIX: u8 = 0x07;

// State variable keys
const LATEST_CONSENSUS_STATE_EPOCH_KEY: [u8; 2] = [STATE_PREFIX, 0];
const LATEST_FINALIZED_HEADER_EPOCH_KEY: [u8; 2] = [STATE_PREFIX, 1];
const LATEST_CHECKPOINT_EPOCH_KEY: [u8; 2] = [STATE_PREFIX, 2];
const CHECKPOINT_IMPORT_KEY: [u8; 2] = [STATE_PREFIX, 3];
const PENDING_IMPORT_STATE_KEY: [u8; 2] = [STATE_PREFIX, 4];
const PENDING_IMPORT_RECORD_KEY: [u8; 2] = [STATE_PREFIX, 5];

/// Durable authorization for the syncer to skip history covered by an import.
/// Retained across restarts, including when checkpoint files are no longer supplied.
#[derive(Clone, Debug)]
pub struct CheckpointImport<V: Variant> {
    pub processed_height: u64,
    pub config_digest: [u8; 32],
    pub finalized_header: FinalizedHeader<bls12381_multisig::Scheme<PublicKey, V>>,
    pub last_block: Option<Block>,
}

pub struct FinalizerState<E: BufferPooler + Clock + Storage + Metrics, V: Variant> {
    store: Option<Db<E, FixedBytes<64>, Value<V>, EightCap>>,
    cancellation_token: CancellationToken,
}

impl<E: BufferPooler + Clock + Storage + Metrics, V: Variant> FinalizerState<E, V> {
    pub async fn new(
        context: E,
        cfg: Config<EightCap, ((), ())>,
        cancellation_token: CancellationToken,
    ) -> Self {
        let store = Db::<_, FixedBytes<64>, Value<V>, EightCap>::init(context, cfg)
            .await
            .expect("failed to initialize unified store");

        Self {
            store: Some(store),
            cancellation_token,
        }
    }

    /// Log a database error, initiate graceful shutdown, and return the error so callers
    /// can propagate it and fence any consensus-critical side effects that must not run on
    /// state that failed to persist.
    fn handle_db_error(&self, e: impl std::fmt::Display, op: &str) -> anyhow::Error {
        error!(target: "critical", %e, op, "fatal database error, initiating shutdown");
        #[cfg(feature = "prom")]
        metrics::counter!("critical_errors_total", "reason" => "fatal_db_error", "severity" => "critical").increment(1);
        self.cancellation_token.cancel();
        anyhow::anyhow!("fatal database error in {op}: {e}")
    }

    pub fn ensure_healthy(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.cancellation_token.is_cancelled(),
            "finalizer database recovery failed"
        );
        Ok(())
    }

    fn store(&self) -> &Db<E, FixedBytes<64>, Value<V>, EightCap> {
        self.store
            .as_ref()
            .expect("finalizer store unavailable after interrupted mutation")
    }

    async fn update(
        &mut self,
        key: FixedBytes<64>,
        value: Option<Value<V>>,
        op: &str,
    ) -> anyhow::Result<()> {
        let Some(store) = self.store.take() else {
            return Err(self.handle_db_error("store unavailable", op));
        };
        match store.apply_batch([(key, value)].into()).await {
            Ok((store, _)) => {
                self.store = Some(store);
                Ok(())
            }
            Err(e) => Err(self.handle_db_error(e, op)),
        }
    }

    fn pad_key(key: &[u8]) -> FixedBytes<64> {
        let mut padded = [0u8; 64];
        let len = key.len().min(64);
        padded[..len].copy_from_slice(&key[..len]);
        FixedBytes::new(padded)
    }

    fn make_consensus_state_key(epoch: u64) -> FixedBytes<64> {
        let mut key = [0u8; 64];
        key[0] = CONSENSUS_STATE_PREFIX;
        // Use little-endian so varying bytes come first (for EightCap translator)
        key[1..9].copy_from_slice(&epoch.to_le_bytes());
        FixedBytes::new(key)
    }

    fn make_finalized_header_key(epoch: u64) -> FixedBytes<64> {
        let mut key = [0u8; 64];
        key[0] = FINALIZED_HEADER_PREFIX;
        // Use little-endian so varying bytes come first (for EightCap translator)
        key[1..9].copy_from_slice(&epoch.to_le_bytes());
        FixedBytes::new(key)
    }

    fn make_checkpoint_key(epoch: u64) -> FixedBytes<64> {
        let mut key = [0u8; 64];
        key[0] = CHECKPOINT_PREFIX;
        // Use little-endian so varying bytes come first (for EightCap translator)
        key[1..9].copy_from_slice(&epoch.to_le_bytes());
        FixedBytes::new(key)
    }

    // State variable operations
    async fn get_latest_consensus_state_epoch(&self) -> u64 {
        let key = Self::pad_key(&LATEST_CONSENSUS_STATE_EPOCH_KEY);
        match self.store().get(&key).await {
            Ok(Some(Value::U64(epoch))) => epoch,
            Ok(_) => 0,
            Err(e) => {
                self.handle_db_error(e, "get_latest_consensus_state_epoch");
                0
            }
        }
    }

    async fn set_latest_consensus_state_epoch(&mut self, epoch: u64) -> anyhow::Result<()> {
        let key = Self::pad_key(&LATEST_CONSENSUS_STATE_EPOCH_KEY);
        self.update(
            key,
            Some(Value::U64(epoch)),
            "set_latest_consensus_state_epoch",
        )
        .await
    }

    // FinalizedHeader epoch tracking operations
    async fn get_latest_finalized_header_epoch(&self) -> u64 {
        let key = Self::pad_key(&LATEST_FINALIZED_HEADER_EPOCH_KEY);
        match self.store().get(&key).await {
            Ok(Some(Value::U64(epoch))) => epoch,
            Ok(_) => 0,
            Err(e) => {
                self.handle_db_error(e, "get_latest_finalized_header_epoch");
                0
            }
        }
    }

    async fn set_latest_finalized_header_epoch(&mut self, epoch: u64) -> anyhow::Result<()> {
        let key = Self::pad_key(&LATEST_FINALIZED_HEADER_EPOCH_KEY);
        self.update(
            key,
            Some(Value::U64(epoch)),
            "set_latest_finalized_header_epoch",
        )
        .await
    }

    // Checkpoint epoch tracking operations
    async fn get_latest_checkpoint_epoch(&self) -> u64 {
        let key = Self::pad_key(&LATEST_CHECKPOINT_EPOCH_KEY);
        match self.store().get(&key).await {
            Ok(Some(Value::U64(epoch))) => epoch,
            Ok(_) => 0,
            Err(e) => {
                self.handle_db_error(e, "get_latest_checkpoint_epoch");
                0
            }
        }
    }

    async fn set_latest_checkpoint_epoch(&mut self, epoch: u64) -> anyhow::Result<()> {
        let key = Self::pad_key(&LATEST_CHECKPOINT_EPOCH_KEY);
        self.update(key, Some(Value::U64(epoch)), "set_latest_checkpoint_epoch")
            .await
    }

    // ConsensusState blob operations
    pub async fn store_consensus_state(
        &mut self,
        epoch: u64,
        state: &ConsensusState,
    ) -> anyhow::Result<()> {
        let key = Self::make_consensus_state_key(epoch);
        self.update(
            key,
            Some(Value::ConsensusState(Box::new(state.clone()))),
            "store_consensus_state",
        )
        .await?;

        // Update the latest epoch tracker
        let current_latest = self.get_latest_consensus_state_epoch().await;
        if epoch >= current_latest {
            self.set_latest_consensus_state_epoch(epoch).await?;
        }
        Ok(())
    }

    pub async fn get_consensus_state(&self, epoch: u64) -> Option<ConsensusState> {
        let key = Self::make_consensus_state_key(epoch);
        match self.store().get(&key).await {
            Ok(Some(Value::ConsensusState(state))) => Some(*state),
            Ok(_) => None,
            Err(e) => {
                self.handle_db_error(e, "get_consensus_state");
                None
            }
        }
    }

    pub async fn get_latest_consensus_state(&self) -> Option<ConsensusState> {
        let key = Self::pad_key(&LATEST_CONSENSUS_STATE_EPOCH_KEY);
        match self.store().get(&key).await {
            Ok(Some(Value::U64(latest_epoch))) => self.get_consensus_state(latest_epoch).await,
            Ok(_) => None,
            Err(e) => {
                self.handle_db_error(e, "get_latest_consensus_state");
                None
            }
        }
    }

    pub async fn delete_consensus_state(&mut self, epoch: u64) {
        let _ = self
            .update(
                Self::make_consensus_state_key(epoch),
                None,
                "delete_consensus_state",
            )
            .await;
    }

    // Checkpoint operations

    pub async fn store_finalized_checkpoint(
        &mut self,
        epoch: u64,
        checkpoint: &Checkpoint,
        last_block: Block,
    ) -> anyhow::Result<()> {
        let key = Self::make_checkpoint_key(epoch);
        self.update(
            key,
            Some(Value::Checkpoint(Box::new((
                checkpoint.clone(),
                last_block,
            )))),
            "store_finalized_checkpoint",
        )
        .await?;

        // Update the latest checkpoint epoch tracker
        let current_latest = self.get_latest_checkpoint_epoch().await;
        if epoch >= current_latest {
            self.set_latest_checkpoint_epoch(epoch).await?;
        }
        Ok(())
    }

    #[allow(unused)]
    pub async fn get_finalized_checkpoint(&self, epoch: u64) -> Option<(Checkpoint, Block)> {
        let key = Self::make_checkpoint_key(epoch);
        match self.store().get(&key).await {
            Ok(Some(Value::Checkpoint(checkpoint))) => Some(*checkpoint),
            Ok(_) => None,
            Err(e) => {
                self.handle_db_error(e, "get_finalized_checkpoint");
                None
            }
        }
    }

    pub async fn get_latest_finalized_checkpoint(&self) -> (Option<(Checkpoint, Block)>, u64) {
        let latest_epoch = self.get_latest_checkpoint_epoch().await;
        let checkpoint = self.get_finalized_checkpoint(latest_epoch).await;
        (checkpoint, latest_epoch)
    }

    // FinalizedHeader operations
    pub async fn store_finalized_header(
        &mut self,
        epoch: u64,
        header: &FinalizedHeader<bls12381_multisig::Scheme<PublicKey, V>>,
    ) -> anyhow::Result<()> {
        let key = Self::make_finalized_header_key(epoch);
        self.update(
            key,
            Some(Value::FinalizedHeader(Box::new(header.clone()))),
            "store_finalized_header",
        )
        .await?;

        // Update the latest finalized header epoch tracker
        let current_latest = self.get_latest_finalized_header_epoch().await;
        if epoch >= current_latest {
            self.set_latest_finalized_header_epoch(epoch).await?;
        }
        Ok(())
    }

    #[allow(unused)]
    pub async fn get_finalized_header(
        &self,
        epoch: u64,
    ) -> Option<FinalizedHeader<bls12381_multisig::Scheme<PublicKey, V>>> {
        let key = Self::make_finalized_header_key(epoch);
        match self.store().get(&key).await {
            Ok(Some(Value::FinalizedHeader(header))) => Some(*header),
            Ok(_) => None,
            Err(e) => {
                self.handle_db_error(e, "get_finalized_header");
                None
            }
        }
    }

    pub async fn get_most_recent_finalized_header(
        &self,
    ) -> Option<FinalizedHeader<bls12381_multisig::Scheme<PublicKey, V>>> {
        let latest_epoch = self.get_latest_finalized_header_epoch().await;
        self.get_finalized_header(latest_epoch).await
    }

    pub async fn get_checkpoint_import(&self) -> anyhow::Result<Option<CheckpointImport<V>>> {
        match self
            .store()
            .get(&Self::pad_key(&CHECKPOINT_IMPORT_KEY))
            .await
        {
            Ok(Some(Value::CheckpointImport(record))) => Ok(Some(*record)),
            Ok(None) => Ok(None),
            Ok(_) => Err(self.handle_db_error("wrong import record type", "get_checkpoint_import")),
            Err(e) => Err(self.handle_db_error(e, "get_checkpoint_import")),
        }
    }

    /// Inspect staged artifacts for startup conflict checks; not skip authorization.
    pub async fn get_pending_import(
        &self,
    ) -> anyhow::Result<Option<(ConsensusState, CheckpointImport<V>)>> {
        let state = self
            .store()
            .get(&Self::pad_key(&PENDING_IMPORT_STATE_KEY))
            .await
            .map_err(|e| self.handle_db_error(e, "get_pending_import"))?;
        let record = self
            .store()
            .get(&Self::pad_key(&PENDING_IMPORT_RECORD_KEY))
            .await
            .map_err(|e| self.handle_db_error(e, "get_pending_import"))?;
        match (state, record) {
            (None, None) => Ok(None),
            (Some(Value::ConsensusState(state)), Some(Value::CheckpointImport(record))) => {
                Ok(Some((*state, *record)))
            }
            _ => Err(self.handle_db_error("incomplete pending import", "get_pending_import")),
        }
    }

    pub(crate) async fn stage_checkpoint_import(
        &mut self,
        state: &ConsensusState,
        record: &CheckpointImport<V>,
    ) -> anyhow::Result<()> {
        self.commit_updates(vec![
            (
                Self::pad_key(&PENDING_IMPORT_STATE_KEY),
                Some(Value::ConsensusState(Box::new(state.clone()))),
            ),
            (
                Self::pad_key(&PENDING_IMPORT_RECORD_KEY),
                Some(Value::CheckpointImport(Box::new(record.clone()))),
            ),
        ])
        .await
    }

    pub(crate) async fn discard_pending_import(&mut self) -> anyhow::Result<()> {
        self.commit_updates(vec![
            (Self::pad_key(&PENDING_IMPORT_STATE_KEY), None),
            (Self::pad_key(&PENDING_IMPORT_RECORD_KEY), None),
        ])
        .await
    }

    async fn commit_updates(
        &mut self,
        updates: Vec<(FixedBytes<64>, Option<Value<V>>)>,
    ) -> anyhow::Result<()> {
        let store = self
            .store
            .take()
            .ok_or_else(|| self.handle_db_error("store unavailable", "checkpoint import"))?;
        let (store, _) = store
            .apply_batch(updates.into_iter().collect())
            .await
            .map_err(|e| self.handle_db_error(e, "checkpoint import"))?;
        self.store = Some(store);
        self.commit().await
    }

    /// Publish state, latest-state pointer, and skip authorization in one journal
    /// batch, then sync. QMDB recovery rewinds incomplete/uncommitted batches.
    pub(crate) async fn import_checkpoint(
        &mut self,
        state: &ConsensusState,
        record: CheckpointImport<V>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            state.get_latest_height() == record.processed_height,
            "import height mismatch"
        );
        self.commit_updates(vec![
            (
                Self::make_consensus_state_key(state.get_epoch()),
                Some(Value::ConsensusState(Box::new(state.clone()))),
            ),
            (
                Self::pad_key(&LATEST_CONSENSUS_STATE_EPOCH_KEY),
                Some(Value::U64(state.get_epoch())),
            ),
            (
                Self::pad_key(&CHECKPOINT_IMPORT_KEY),
                Some(Value::CheckpointImport(Box::new(record))),
            ),
            (Self::pad_key(&PENDING_IMPORT_STATE_KEY), None),
            (Self::pad_key(&PENDING_IMPORT_RECORD_KEY), None),
        ])
        .await
    }

    // Commit all pending changes to the database
    pub async fn commit(&mut self) -> anyhow::Result<()> {
        let Some(store) = self.store.take() else {
            return Err(self.handle_db_error("store unavailable", "commit"));
        };
        match store.commit().await {
            Ok(store) => {
                self.store = Some(store);
                Ok(())
            }
            Err(e) => Err(self.handle_db_error(e, "commit")),
        }
    }
}

#[derive(Clone)]
enum Value<V: Variant> {
    U64(u64),
    CheckpointImport(Box<CheckpointImport<V>>),
    ConsensusState(Box<ConsensusState>),
    Checkpoint(Box<(Checkpoint, Block)>),
    FinalizedHeader(Box<FinalizedHeader<bls12381_multisig::Scheme<PublicKey, V>>>),
}

impl<V: Variant> EncodeSize for Value<V> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::U64(_) => 8,
            Self::CheckpointImport(record) => {
                8 + 32 + record.finalized_header.encode_size() + record.last_block.encode_size()
            }
            Self::ConsensusState(state) => state.encode_size(),
            Self::Checkpoint(checkpoint) => checkpoint.encode_size(),
            Self::FinalizedHeader(header) => header.encode_size(),
        }
    }
}

impl<V: Variant> Read for Value<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let value_type = buf.try_get_u8().map_err(|_| Error::EndOfBuffer)?;
        match value_type {
            0x01 => Ok(Self::U64(
                buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?,
            )),
            0x08 => {
                let processed_height = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
                let mut config_digest = [0; 32];
                buf.try_copy_to_slice(&mut config_digest)
                    .map_err(|_| Error::EndOfBuffer)?;
                Ok(Self::CheckpointImport(Box::new(CheckpointImport {
                    processed_height,
                    config_digest,
                    finalized_header: FinalizedHeader::read_cfg(buf, &())?,
                    last_block: Option::<Block>::read_cfg(buf, &())?,
                })))
            }
            0x05 => Ok(Self::ConsensusState(Box::new(ConsensusState::read_cfg(
                buf,
                &(),
            )?))),
            0x06 => Ok(Self::Checkpoint(Box::new((
                Checkpoint::read_cfg(buf, &())?,
                Block::read_cfg(buf, &())?,
            )))),
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
            Self::CheckpointImport(record) => {
                buf.put_u8(0x08);
                buf.put_u64(record.processed_height);
                buf.put_slice(&record.config_digest);
                record.finalized_header.write(buf);
                record.last_block.write(buf);
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
    use commonware_codec::ReadExt;
    use commonware_consensus::simplex::types::{Finalization, Proposal};
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::bls12381::primitives::{
        group::Private,
        ops::{aggregate::Signature, sign_message},
        variant::MinPk,
    };
    use commonware_cryptography::certificate::Signers;
    use commonware_cryptography::certificate::bls12381_multisig::Certificate as BlsCertificate;
    use commonware_math::algebra::Random;
    use commonware_runtime::buffer::paged::CacheRef;
    use commonware_runtime::{Runner as _, deterministic::Runner};
    use commonware_utils::{NZU64, NZUsize, Participant};
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;
    use summit_types::Block;

    #[test]
    fn test_value_read_truncated_input_returns_err() {
        // Empty buffer — must not panic.
        let empty: &[u8] = &[];
        assert!(matches!(
            Value::<MinPk>::read(&mut empty.as_ref()),
            Err(Error::EndOfBuffer)
        ));

        // Tag 0x01 (U64) with 0..8 payload bytes — all truncated.
        for n in 0..8 {
            let mut buf = vec![0x01u8];
            buf.extend(std::iter::repeat_n(0u8, n));
            assert!(matches!(
                Value::<MinPk>::read(&mut buf.as_ref()),
                Err(Error::EndOfBuffer)
            ));
        }
    }

    async fn create_test_db_with_context<
        E: Clock + Storage + Metrics + commonware_runtime::BufferPooler,
        V: Variant,
    >(
        partition: &str,
        context: E,
    ) -> FinalizerState<E, V> {
        let config = Config {
            log: commonware_storage::journal::contiguous::variable::Config {
                partition: format!("{}-log", partition),
                write_buffer: NZUsize!(64 * 1024),
                replay_buffer: NZUsize!(64 * 1024),
                compression: None,
                codec_config: ((), ()),
                items_per_section: NZU64!(4),
                page_cache: CacheRef::from_pooler(
                    &context,
                    std::num::NonZero::new(77u16).unwrap(),
                    NZUsize!(9),
                ),
            },
            translator: EightCap,
            init_cache_size: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(64 * 1024),
        };
        FinalizerState::<E, V>::new(context, config, CancellationToken::new()).await
    }

    fn create_dummy_signature() -> Signature<MinPk> {
        // Create a deterministic private key and sign a dummy message to get a valid G2 point
        let mut rng = StdRng::seed_from_u64(42);
        let private = Private::random(&mut rng);
        let g2_signature = sign_message::<MinPk>(&private, b"", b"test message");

        // Encode the G2 signature and decode it as Signature<MinPk>
        use commonware_codec::{DecodeExt as _, Encode as _};
        let encoded = g2_signature.encode();
        Signature::<MinPk>::decode(encoded).expect("valid signature")
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
            db.store_consensus_state(42, &consensus_state)
                .await
                .unwrap();
            db.commit().await.unwrap();

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
            db.store_consensus_state(100, &newer_state).await.unwrap();
            db.commit().await.unwrap();

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
            let header = summit_types::Header::new(
                [1u8; 32].into(), // parent
                100,              // height
                1234567890,       // timestamp
                0,                // epoch
                1,                // view
                [2u8; 32].into(), // payload_hash
                [3u8; 32].into(), // execution_request_hash
                [4u8; 32].into(), // checkpoint_hash
                [5u8; 32].into(), // prev_epoch_header_hash
                Vec::new(),       // added_validators
                Vec::new(),       // removed_validators
                [0u8; 32],        // parent_beacon_block_root
            );

            // Create finalization proof
            let proposal = Proposal {
                round: Round::new(Epoch::new(header.epoch()), View::new(header.view())),
                parent: View::new(header.height()),
                payload: header.get_digest(),
            };
            let finalized = Finalization {
                proposal,
                certificate: BlsCertificate::<MinPk> {
                    signers: Signers::new(3, [0, 1, 2].map(Participant::new)).unwrap(),
                    signature: create_dummy_signature().into(), // Valid dummy signature for test
                },
            };
            let finalized_header =
                summit_types::FinalizedHeader::new_unchecked(header.clone(), finalized, 3);

            // Test that no header exists initially
            assert!(db.get_finalized_header(100).await.is_none());

            // Store the finalized header at height 100
            db.store_finalized_header(100, &finalized_header)
                .await
                .unwrap();
            db.commit().await.unwrap();

            // Retrieve the finalized header
            let retrieved = db.get_finalized_header(100).await;
            assert!(retrieved.is_some());
            let retrieved = retrieved.unwrap();
            assert_eq!(retrieved.header().height(), header.height());
            assert_eq!(retrieved.header().get_digest(), header.get_digest());
            assert_eq!(retrieved.header().timestamp(), header.timestamp());

            // Test that non-existent header returns None
            assert!(db.get_finalized_header(200).await.is_none());

            // Store another header at different height
            let header2 = summit_types::Header::new(
                [5u8; 32].into(), // parent
                200,              // height
                1234567900,       // timestamp
                0,                // epoch
                2,                // view
                [6u8; 32].into(), // payload_hash
                [7u8; 32].into(), // execution_request_hash
                [8u8; 32].into(), // checkpoint_hash
                [9u8; 32].into(), // prev_epoch_header_hash
                Vec::new(),       // added_validators
                Vec::new(),       // removed_validators
                [0u8; 32],        // parent_beacon_block_root
            );
            let proposal2 = Proposal {
                round: Round::new(Epoch::new(header2.epoch()), View::new(header2.view())),
                parent: View::new(header2.height()),
                payload: header2.get_digest(),
            };
            let finalized2 = Finalization {
                proposal: proposal2,
                certificate: BlsCertificate::<MinPk> {
                    signers: Signers::new(3, [0, 1, 2].map(Participant::new)).unwrap(),
                    signature: create_dummy_signature().into(),
                },
            };
            let finalized_header2 =
                summit_types::FinalizedHeader::new_unchecked(header2.clone(), finalized2, 3);
            db.store_finalized_header(200, &finalized_header2)
                .await
                .unwrap();
            db.commit().await.unwrap();

            // Both headers should be accessible
            let h1 = db.get_finalized_header(100).await.unwrap();
            let h2 = db.get_finalized_header(200).await.unwrap();
            assert_eq!(h1.header().height(), 100);
            assert_eq!(h2.header().height(), 200);
            assert_ne!(h1.header().get_digest(), h2.header().get_digest());

            // Test get_most_recent_finalized_header returns the latest header
            let most_recent = db.get_most_recent_finalized_header().await;
            assert!(most_recent.is_some());
            let most_recent = most_recent.unwrap();
            assert_eq!(most_recent.header().height(), 200);
            assert_eq!(most_recent.header().get_digest(), header2.get_digest());
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
            let header1 = summit_types::Header::new(
                [1u8; 32].into(), // parent
                100,              // height
                1234567890,       // timestamp
                0,                // epoch
                1,                // view
                [2u8; 32].into(), // payload_hash
                [3u8; 32].into(), // execution_request_hash
                [4u8; 32].into(), // checkpoint_hash
                [5u8; 32].into(), // prev_epoch_header_hash
                Vec::new(),       // added_validators
                Vec::new(),       // removed_validators
                [0u8; 32],        // parent_beacon_block_root
            );
            let proposal1 = Proposal {
                round: Round::new(Epoch::new(header1.epoch()), View::new(header1.view())),
                parent: View::new(header1.height()),
                payload: header1.get_digest(),
            };

            let finalized1 = Finalization {
                proposal: proposal1,
                certificate: BlsCertificate::<MinPk> {
                    signers: Signers::new(3, [0, 1, 2].map(Participant::new)).unwrap(),
                    signature: create_dummy_signature().into(),
                },
            };
            let finalized_header1 =
                summit_types::FinalizedHeader::new_unchecked(header1.clone(), finalized1, 3);

            let header3 = summit_types::Header::new(
                [7u8; 32].into(),  // parent
                300,               // height
                1234567920,        // timestamp
                0,                 // epoch
                3,                 // view
                [8u8; 32].into(),  // payload_hash
                [9u8; 32].into(),  // execution_request_hash
                [10u8; 32].into(), // checkpoint_hash
                [11u8; 32].into(), // prev_epoch_header_hash
                Vec::new(),        // added_validators
                Vec::new(),        // removed_validators
                [0u8; 32],         // parent_beacon_block_root
            );
            let proposal3 = Proposal {
                round: Round::new(Epoch::new(header3.epoch()), View::new(header3.view())),
                parent: View::new(header3.height()),
                payload: header3.get_digest(),
            };

            let finalized3 = Finalization {
                proposal: proposal3,
                certificate: BlsCertificate::<MinPk> {
                    signers: Signers::new(3, [0, 1, 2].map(Participant::new)).unwrap(),
                    signature: create_dummy_signature().into(),
                },
            };
            let finalized_header3 =
                summit_types::FinalizedHeader::new_unchecked(header3.clone(), finalized3, 3);

            let header2 = summit_types::Header::new(
                [5u8; 32].into(), // parent
                200,              // height
                1234567900,       // timestamp
                0,                // epoch
                2,                // view
                [6u8; 32].into(), // payload_hash
                [7u8; 32].into(), // execution_request_hash
                [8u8; 32].into(), // checkpoint_hash
                [9u8; 32].into(), // prev_epoch_header_hash
                Vec::new(),       // added_validators
                Vec::new(),       // removed_validators
                [0u8; 32],        // parent_beacon_block_root
            );
            let proposal2 = Proposal {
                round: Round::new(Epoch::new(header2.epoch()), View::new(header2.view())),
                parent: View::new(header2.height()),
                payload: header2.get_digest(),
            };

            let finalized2 = Finalization {
                proposal: proposal2,
                certificate: BlsCertificate::<MinPk> {
                    signers: Signers::new(3, [0, 1, 2].map(Participant::new)).unwrap(),
                    signature: create_dummy_signature().into(),
                },
            };
            let finalized_header2 =
                summit_types::FinalizedHeader::new_unchecked(header2.clone(), finalized2, 3);

            // Store headers in non-sequential order: 100, 300, 200
            db.store_finalized_header(100, &finalized_header1)
                .await
                .unwrap();
            db.commit().await.unwrap();

            // Most recent should be height 100
            let most_recent = db.get_most_recent_finalized_header().await.unwrap();
            assert_eq!(most_recent.header().height(), 100);
            assert_eq!(most_recent.header().get_digest(), header1.get_digest());

            // Store height 300
            db.store_finalized_header(300, &finalized_header3)
                .await
                .unwrap();
            db.commit().await.unwrap();

            // Most recent should now be height 300
            let most_recent = db.get_most_recent_finalized_header().await.unwrap();
            assert_eq!(most_recent.header().height(), 300);
            assert_eq!(most_recent.header().get_digest(), header3.get_digest());

            // Store height 200 (lower than current max)
            db.store_finalized_header(200, &finalized_header2)
                .await
                .unwrap();
            db.commit().await.unwrap();

            // Most recent should still be height 300
            let most_recent = db.get_most_recent_finalized_header().await.unwrap();
            assert_eq!(most_recent.header().height(), 300);
            assert_eq!(most_recent.header().get_digest(), header3.get_digest());

            // Verify all headers are still individually accessible
            let h1 = db.get_finalized_header(100).await.unwrap();
            let h2 = db.get_finalized_header(200).await.unwrap();
            let h3 = db.get_finalized_header(300).await.unwrap();
            assert_eq!(h1.header().height(), 100);
            assert_eq!(h2.header().height(), 200);
            assert_eq!(h3.header().height(), 300);
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
            assert!(db.get_finalized_checkpoint(0).await.is_none());
            assert!(db.get_latest_finalized_checkpoint().await.0.is_none());

            // Store finalized checkpoint for epoch 0
            db.store_finalized_checkpoint(0, &finalized_checkpoint1, Block::genesis([0; 32]))
                .await
                .unwrap();
            db.commit().await.unwrap();

            // Retrieve finalized checkpoint
            let retrieved_finalized = db.get_finalized_checkpoint(0).await;
            assert!(retrieved_finalized.is_some());
            let (retrieved_finalized, _) = retrieved_finalized.unwrap();
            assert_eq!(retrieved_finalized.data, finalized_checkpoint1.data);
            assert_eq!(retrieved_finalized.digest, finalized_checkpoint1.digest);

            // Test that latest checkpoint returns epoch 0 checkpoint
            let (latest, _) = db.get_latest_finalized_checkpoint().await.0.unwrap();
            assert_eq!(latest.digest, finalized_checkpoint1.digest);

            // Store checkpoint for epoch 1
            db.store_finalized_checkpoint(1, &finalized_checkpoint2, Block::genesis([0; 32]))
                .await
                .unwrap();
            db.commit().await.unwrap();

            // Both checkpoints should be accessible
            let (checkpoint0, _) = db.get_finalized_checkpoint(0).await.unwrap();
            let (checkpoint1, _) = db.get_finalized_checkpoint(1).await.unwrap();
            assert_eq!(checkpoint0.digest, finalized_checkpoint1.digest);
            assert_eq!(checkpoint1.digest, finalized_checkpoint2.digest);
            assert_ne!(checkpoint0.digest, checkpoint1.digest);

            // Latest should now return epoch 1 checkpoint
            let (latest, _) = db.get_latest_finalized_checkpoint().await.0.unwrap();
            assert_eq!(latest.digest, finalized_checkpoint2.digest);
        });
    }

    #[test]
    fn test_checkpoint_out_of_order_storage() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(6);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db =
                create_test_db_with_context::<_, MinPk>("test_checkpoint_out_of_order", context)
                    .await;

            // Create test checkpoints with different heights to ensure different digests
            let mut state5 = ConsensusState::default();
            state5.set_latest_height(500);
            let checkpoint5 = summit_types::checkpoint::Checkpoint::new(&state5);

            let mut state3 = ConsensusState::default();
            state3.set_latest_height(300);
            let checkpoint3 = summit_types::checkpoint::Checkpoint::new(&state3);

            let mut state7 = ConsensusState::default();
            state7.set_latest_height(700);
            let checkpoint7 = summit_types::checkpoint::Checkpoint::new(&state7);

            // Store checkpoints out of order: 5, then 3, then 7
            db.store_finalized_checkpoint(5, &checkpoint5, Block::genesis([0; 32]))
                .await
                .unwrap();
            db.commit().await.unwrap();

            // Latest should be epoch 5
            let (latest, _) = db.get_latest_finalized_checkpoint().await.0.unwrap();
            assert_eq!(latest.digest, checkpoint5.digest);

            // Store epoch 3 (older than current latest)
            db.store_finalized_checkpoint(3, &checkpoint3, Block::genesis([0; 32]))
                .await
                .unwrap();
            db.commit().await.unwrap();

            // Latest should still be epoch 5, not 3
            let (latest, _) = db.get_latest_finalized_checkpoint().await.0.unwrap();
            assert_eq!(latest.digest, checkpoint5.digest);

            // Store epoch 7 (newer than current latest)
            db.store_finalized_checkpoint(7, &checkpoint7, Block::genesis([0; 32]))
                .await
                .unwrap();
            db.commit().await.unwrap();

            // Latest should now be epoch 7
            let (latest, _) = db.get_latest_finalized_checkpoint().await.0.unwrap();
            assert_eq!(latest.digest, checkpoint7.digest);

            // All checkpoints should still be individually accessible
            let (cp3, _) = db.get_finalized_checkpoint(3).await.unwrap();
            let (cp5, _) = db.get_finalized_checkpoint(5).await.unwrap();
            let (cp7, _) = db.get_finalized_checkpoint(7).await.unwrap();
            assert_eq!(cp3.digest, checkpoint3.digest);
            assert_eq!(cp5.digest, checkpoint5.digest);
            assert_eq!(cp7.digest, checkpoint7.digest);
        });
    }

    #[test]
    fn test_checkpoint_overwrite() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(7);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db =
                create_test_db_with_context::<_, MinPk>("test_checkpoint_overwrite", context).await;

            // Create two different checkpoints for the same epoch
            let mut state1 = ConsensusState::default();
            state1.set_latest_height(100);

            let checkpoint1 = summit_types::checkpoint::Checkpoint::new(&state1);

            let mut state2 = ConsensusState::default();
            state2.set_latest_height(200);
            let checkpoint2 = summit_types::checkpoint::Checkpoint::new(&state2);

            // Store first checkpoint for epoch 2
            db.store_finalized_checkpoint(2, &checkpoint1, Block::genesis([0; 32]))
                .await
                .unwrap();
            db.commit().await.unwrap();

            let (retrieved, _) = db.get_finalized_checkpoint(2).await.unwrap();
            assert_eq!(retrieved.digest, checkpoint1.digest);

            // Overwrite with second checkpoint for the same epoch 2
            db.store_finalized_checkpoint(2, &checkpoint2, Block::genesis([0; 32]))
                .await
                .unwrap();
            db.commit().await.unwrap();

            // Should now return the second checkpoint
            let (retrieved, _) = db.get_finalized_checkpoint(2).await.unwrap();
            assert_eq!(retrieved.digest, checkpoint2.digest);
            assert_ne!(retrieved.digest, checkpoint1.digest);

            // Latest should still point to epoch 2
            let (latest, _) = db.get_latest_finalized_checkpoint().await.0.unwrap();
            assert_eq!(latest.digest, checkpoint2.digest);
        });
    }

    #[test]
    fn test_checkpoint_gaps_in_epochs() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(8);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db =
                create_test_db_with_context::<_, MinPk>("test_checkpoint_gaps", context).await;

            // Create checkpoints for non-consecutive epochs
            let mut state0 = ConsensusState::default();
            state0.set_latest_height(100);
            let checkpoint0 = summit_types::checkpoint::Checkpoint::new(&state0);

            let mut state2 = ConsensusState::default();
            state2.set_latest_height(300);
            let checkpoint2 = summit_types::checkpoint::Checkpoint::new(&state2);

            let mut state5 = ConsensusState::default();
            state5.set_latest_height(600);
            let checkpoint5 = summit_types::checkpoint::Checkpoint::new(&state5);

            // Store checkpoints for epochs 0, 2, and 5 (skipping 1, 3, 4)
            db.store_finalized_checkpoint(0, &checkpoint0, Block::genesis([0; 32]))
                .await
                .unwrap();
            db.commit().await.unwrap();

            db.store_finalized_checkpoint(2, &checkpoint2, Block::genesis([0; 32]))
                .await
                .unwrap();
            db.commit().await.unwrap();

            db.store_finalized_checkpoint(5, &checkpoint5, Block::genesis([0; 32]))
                .await
                .unwrap();
            db.commit().await.unwrap();

            // All stored checkpoints should be retrievable
            let (cp0, _) = db.get_finalized_checkpoint(0).await.unwrap();
            let (cp2, _) = db.get_finalized_checkpoint(2).await.unwrap();
            let (cp5, _) = db.get_finalized_checkpoint(5).await.unwrap();
            assert_eq!(cp0.digest, checkpoint0.digest);
            assert_eq!(cp2.digest, checkpoint2.digest);
            assert_eq!(cp5.digest, checkpoint5.digest);

            // Missing epochs should return None
            assert!(db.get_finalized_checkpoint(1).await.is_none());
            assert!(db.get_finalized_checkpoint(3).await.is_none());
            assert!(db.get_finalized_checkpoint(4).await.is_none());

            // Latest should return epoch 5 (highest stored epoch)
            let (latest, epoch) = db.get_latest_finalized_checkpoint().await;
            assert_eq!(latest.unwrap().0.digest, checkpoint5.digest);
            assert_eq!(epoch, 5u64);
        });
    }
}
