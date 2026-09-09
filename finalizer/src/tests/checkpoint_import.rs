use super::mocks::{MockEngineClient, make_finalization};
use crate::{
    db::{self, CheckpointImport, FinalizerState},
    startup,
};
use alloy_primitives::Address;
use alloy_rpc_types_engine::ForkchoiceState;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::bls12381::primitives::{
    group,
    variant::{MinPk, Variant},
};
use commonware_cryptography::{Signer as _, bls12381, ed25519};
use commonware_runtime::{
    Runner as _, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, Runner},
};
use commonware_utils::{NZU16, NZU64, NZUsize, TryCollect, ordered::BiMap};
use summit_types::{
    Block, FinalizedHeader, PublicKey,
    account::{ValidatorAccount, ValidatorStatus},
    chain_domain,
    checkpoint::Checkpoint,
    consensus_state::ConsensusState,
    scheme::MultisigScheme,
};
use tokio_util::sync::CancellationToken;

const DOMAIN: [u8; 32] = [7; 32];

fn checkpoint() -> (ConsensusState, Block, FinalizedHeader<MultisigScheme>) {
    let node = ed25519::PrivateKey::from_seed(1).public_key();
    let key = bls12381::PrivateKey::from_seed(2);
    let public = key.public_key();
    let mut state = ConsensusState::new(
        ForkchoiceState {
            head_block_hash: [1; 32].into(),
            safe_block_hash: [1; 32].into(),
            finalized_block_hash: [1; 32].into(),
        },
        32_000_000_000,
        NZU64!(10),
        1000,
        Address::ZERO,
        100,
        100,
        16,
        128,
        1,
        0,
        3,
    );
    state.set_validator_accounts(std::collections::BTreeMap::from([(
        node.as_ref().try_into().unwrap(),
        ValidatorAccount {
            consensus_public_key: public.clone(),
            withdrawal_credentials: Address::ZERO,
            balance: 32_000_000_000,
            status: ValidatorStatus::Active,
            joining_epoch: 0,
            last_deposit_index: 0,
        },
    )]));
    state.set_latest_height(8);
    state.set_view(8);
    state.set_head_digest([8; 32].into());
    state.capture_state_root(8);
    let raw = Checkpoint::new(&state);
    state.set_pending_checkpoint(Some(raw.clone()));
    state.capture_state_root(8);
    let mut payload = Block::genesis([1; 32]).payload;
    payload.payload_inner.payload_inner.block_number = 9;
    payload.payload_inner.payload_inner.block_hash = [9; 32].into();
    payload.payload_inner.payload_inner.parent_hash = [1; 32].into();
    let block = Block::compute_digest(
        state.get_head_digest(),
        9,
        90,
        payload,
        vec![],
        0,
        9,
        Some(raw.digest),
        DOMAIN.into(),
        vec![],
        vec![],
        state.get_state_root(),
    );
    let group_public: &<MinPk as Variant>::Public = public.as_ref();
    let participants: BiMap<PublicKey, <MinPk as Variant>::Public> = [(node, group_public.clone())]
        .into_iter()
        .try_collect()
        .unwrap();
    let scheme = MultisigScheme::signer(
        &chain_domain(DOMAIN),
        participants,
        group::Private::decode(key.encode()).unwrap(),
    )
    .unwrap();
    let certificate = make_finalization(block.digest(), 9, 8, &[scheme], 1);
    let header = FinalizedHeader::new(block.header.clone(), certificate, 1).unwrap();
    (state, block, header)
}

async fn open(context: deterministic::Context) -> FinalizerState<deterministic::Context, MinPk> {
    let cache = CacheRef::from_pooler(&context, NZU16!(4096), NZUsize!(16));
    FinalizerState::new(
        context,
        db::config("import-test", cache),
        CancellationToken::new(),
    )
    .await
}

async fn seed(db: &mut FinalizerState<deterministic::Context, MinPk>, height: u64) {
    let mut state = ConsensusState::default();
    state.set_latest_height(height);
    db.store_consensus_state(state.get_epoch(), &state)
        .await
        .unwrap();
    db.commit().await.unwrap();
}

fn record(
    block: Option<Block>,
    header: FinalizedHeader<MultisigScheme>,
) -> CheckpointImport<MinPk> {
    CheckpointImport {
        processed_height: 8,
        config_digest: DOMAIN,
        finalized_header: header,
        last_block: block,
    }
}

#[test]
fn newer_checkpoint_replaces_nonempty_state_and_survives_without_files() {
    let (_, recovered) = Runner::default().start_and_recover(|context| async move {
        let mut db = open(context).await;
        seed(&mut db, 3).await;
        let (state, block, header) = checkpoint();
        let (selected, imported) = startup::prepare(
            &mut db,
            &mut MockEngineClient::new(),
            state,
            Some(header),
            Some(block),
            DOMAIN,
        )
        .await
        .unwrap();
        assert_eq!(selected.get_latest_height(), 8);
        assert_eq!(imported.unwrap().processed_height, 8);
        assert!(db.get_pending_import().await.unwrap().is_none());
    });
    Runner::from(recovered).start(|context| async move {
        let mut db = open(context).await;
        let (state, imported) = startup::prepare(
            &mut db,
            &mut MockEngineClient::new(),
            ConsensusState::default(),
            None,
            None,
            DOMAIN,
        )
        .await
        .unwrap();
        assert_eq!(state.get_latest_height(), 8);
        assert_eq!(state.get_observers_per_validator(), 16);
        assert_eq!(imported.unwrap().last_block.unwrap().height(), 9);
    });
}

#[test]
fn repeated_checkpoint_import_is_idempotent_and_old_checkpoint_cannot_roll_back() {
    Runner::default().start(|context| async move {
        let mut db = open(context).await;
        let (candidate, block, header) = checkpoint();
        let (mut state, _) = startup::prepare(
            &mut db,
            &mut MockEngineClient::new(),
            candidate.clone(),
            Some(header.clone()),
            Some(block.clone()),
            DOMAIN,
        )
        .await
        .unwrap();
        let (again, _) = startup::prepare(
            &mut db,
            &mut MockEngineClient::new(),
            candidate.clone(),
            Some(header.clone()),
            Some(block.clone()),
            DOMAIN,
        )
        .await
        .unwrap();
        assert_eq!(state.encode(), again.encode());
        state.set_latest_height(12);
        db.store_consensus_state(0, &state).await.unwrap();
        db.commit().await.unwrap();
        let (selected, imported) = startup::prepare(
            &mut db,
            &mut MockEngineClient::new(),
            candidate,
            Some(header),
            Some(block),
            DOMAIN,
        )
        .await
        .unwrap();
        assert_eq!(selected.get_latest_height(), 12);
        assert_eq!(imported.unwrap().processed_height, 8);
    });
}

#[test]
fn older_checkpoint_without_prior_import_does_not_authorize_a_skip() {
    Runner::default().start(|context| async move {
        let mut db = open(context).await;
        seed(&mut db, 20).await;
        let (state, block, header) = checkpoint();
        let (selected, imported) = startup::prepare(
            &mut db,
            &mut MockEngineClient::new(),
            state,
            Some(header),
            Some(block),
            DOMAIN,
        )
        .await
        .unwrap();
        assert_eq!(selected.get_latest_height(), 20);
        assert!(imported.is_none());
    });
}

#[test]
fn conflicting_same_height_state_is_rejected() {
    Runner::default().start(|context| async move {
        let mut db = open(context).await;
        seed(&mut db, 8).await;
        let (state, block, header) = checkpoint();
        assert!(
            startup::prepare(
                &mut db,
                &mut MockEngineClient::new(),
                state,
                Some(header),
                Some(block),
                DOMAIN
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("same height")
        );
        assert!(db.get_checkpoint_import().await.unwrap().is_none());
        assert!(db.get_pending_import().await.unwrap().is_none());
    });
}

#[test]
fn invalid_older_artifacts_are_not_silently_ignored() {
    Runner::default().start(|context| async move {
        let mut db = open(context).await;
        seed(&mut db, 20).await;
        let (mut state, block, header) = checkpoint();
        state.set_observers_per_validator(17);
        assert!(
            startup::prepare(
                &mut db,
                &mut MockEngineClient::new(),
                state,
                Some(header),
                Some(block),
                DOMAIN
            )
            .await
            .is_err()
        );
        assert_eq!(
            db.get_latest_consensus_state()
                .await
                .unwrap()
                .get_latest_height(),
            20
        );
    });
}

#[test]
fn wrong_domain_or_block_is_rejected_before_staging() {
    Runner::default().start(|context| async move {
        let mut db = open(context).await;
        seed(&mut db, 3).await;
        let (state, block, header) = checkpoint();
        assert!(
            startup::prepare(
                &mut db,
                &mut MockEngineClient::new(),
                state.clone(),
                Some(header.clone()),
                Some(block),
                [6; 32]
            )
            .await
            .is_err()
        );
        assert!(
            startup::prepare(
                &mut db,
                &mut MockEngineClient::new(),
                state,
                Some(header),
                Some(Block::genesis([2; 32])),
                DOMAIN
            )
            .await
            .is_err()
        );
        assert!(db.get_pending_import().await.unwrap().is_none());
    });
}

#[test]
fn execution_invalid_rejects_import_and_retains_old_state() {
    Runner::default().start(|context| async move {
        let mut db = open(context).await;
        seed(&mut db, 3).await;
        let mut client = MockEngineClient::new();
        client.queue_commit_hash_invalid(1);
        let (state, block, header) = checkpoint();
        assert!(
            startup::prepare(
                &mut db,
                &mut client,
                state,
                Some(header),
                Some(block),
                DOMAIN
            )
            .await
            .is_err()
        );
        assert_eq!(
            db.get_latest_consensus_state()
                .await
                .unwrap()
                .get_latest_height(),
            3
        );
        assert!(db.get_pending_import().await.unwrap().is_none());
        assert!(db.get_checkpoint_import().await.unwrap().is_none());
    });
}

#[test]
fn execution_transport_error_leaves_recoverable_pending_import() {
    let (_, recovered) = Runner::default().start_and_recover(|context| async move {
        let mut db = open(context).await;
        seed(&mut db, 3).await;
        let mut client = MockEngineClient::new();
        client.fail_commit_hash();
        let (state, block, header) = checkpoint();
        assert!(
            startup::prepare(
                &mut db,
                &mut client,
                state,
                Some(header),
                Some(block),
                DOMAIN
            )
            .await
            .is_err()
        );
        assert!(db.get_pending_import().await.unwrap().is_some());
        assert!(db.get_checkpoint_import().await.unwrap().is_none());
        assert_eq!(
            db.get_latest_consensus_state()
                .await
                .unwrap()
                .get_latest_height(),
            3
        );
    });
    Runner::from(recovered).start(|context| async move {
        let mut db = open(context).await;
        let (state, imported) = startup::prepare(
            &mut db,
            &mut MockEngineClient::new(),
            ConsensusState::default(),
            None,
            None,
            DOMAIN,
        )
        .await
        .unwrap();
        assert_eq!(state.get_latest_height(), 8);
        assert!(imported.is_some());
        assert!(db.get_pending_import().await.unwrap().is_none());
    });
}

#[test]
fn restart_resumes_after_reth_acceptance_before_state_publication() {
    use summit_types::EngineClient as _;
    let (_, recovered) = Runner::default().start_and_recover(|context| async move {
        let mut db = open(context).await;
        seed(&mut db, 3).await;
        let (state, block, header) = checkpoint();
        db.stage_checkpoint_import(&state, &record(Some(block), header))
            .await
            .unwrap();
        assert!(
            MockEngineClient::new()
                .commit_hash(*state.get_forkchoice())
                .await
                .unwrap()
                .is_valid()
        );
        // Crash here: Reth has accepted, but no canonical-state/skip publication.
        assert_eq!(
            db.get_latest_consensus_state()
                .await
                .unwrap()
                .get_latest_height(),
            3
        );
        assert!(db.get_checkpoint_import().await.unwrap().is_none());
    });
    Runner::from(recovered).start(|context| async move {
        let mut db = open(context).await;
        let (state, imported) = startup::prepare(
            &mut db,
            &mut MockEngineClient::new(),
            ConsensusState::default(),
            None,
            None,
            DOMAIN,
        )
        .await
        .unwrap();
        assert_eq!(state.get_latest_height(), 8);
        assert_eq!(imported.unwrap().processed_height, 8);
    });
}

#[test]
fn missing_terminal_block_is_retained_as_a_fetchable_import() {
    Runner::default().start(|context| async move {
        let mut db = open(context).await;
        let (state, _, header) = checkpoint();
        let mut client = MockEngineClient::new();
        client.queue_commit_hash_syncing(2);
        let (state, imported) =
            startup::prepare(&mut db, &mut client, state, Some(header), None, DOMAIN)
                .await
                .unwrap();
        assert_eq!(state.get_latest_height(), 8);
        assert!(imported.unwrap().last_block.is_none());
    });
}

#[test]
fn failed_staging_never_calls_execution_or_returns_skip_authorization() {
    Runner::default().start(|context| async move {
        let mut db = open(context.child("db")).await;
        seed(&mut db, 3).await;
        let mut client = MockEngineClient::new();
        context.storage_fault_config().write().sync_rate =
            Some(commonware_utils::probability!(1.0));
        let (state, block, header) = checkpoint();
        assert!(
            startup::prepare(
                &mut db,
                &mut client,
                state,
                Some(header),
                Some(block),
                DOMAIN
            )
            .await
            .is_err()
        );
        assert_eq!(client.commit_hash_call_count(), 0);
        assert!(db.ensure_healthy().is_err());
    });
}

#[test]
fn failed_publication_recovers_coherent_state_and_authorization() {
    let (_, recovered) = Runner::default().start_and_recover(|context| async move {
        let mut db = open(context.child("db")).await;
        seed(&mut db, 3).await;
        let (state, block, header) = checkpoint();
        let record = record(Some(block), header);
        db.stage_checkpoint_import(&state, &record).await.unwrap();
        context.storage_fault_config().write().sync_rate =
            Some(commonware_utils::probability!(1.0));
        assert!(db.import_checkpoint(&state, record).await.is_err());
        assert!(db.ensure_healthy().is_err());
    });
    Runner::from(recovered).start(|context| async move {
        context.storage_fault_config().write().sync_rate = None;
        let mut db = open(context).await;
        // Failed fsync may have persisted either complete batch. Neither may
        // expose a committed skip paired with the pre-import canonical state.
        let state = db.get_latest_consensus_state().await.unwrap();
        match db.get_checkpoint_import().await.unwrap() {
            Some(record) => assert_eq!(state.get_latest_height(), record.processed_height),
            None => assert!(db.get_pending_import().await.unwrap().is_some()),
        }
        let (state, imported) = startup::prepare(
            &mut db,
            &mut MockEngineClient::new(),
            ConsensusState::default(),
            None,
            None,
            DOMAIN,
        )
        .await
        .unwrap();
        assert_eq!(state.get_latest_height(), 8);
        assert_eq!(imported.unwrap().processed_height, 8);
    });
}
