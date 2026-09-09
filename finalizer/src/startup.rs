//! Checkpoint promotion before network allocation or actor startup.
//!
//! The caller must enforce the checkpoint trust policy (by default, verifying the
//! finalized-header chain against genesis and weak subjectivity), and check all
//! supplied history against local finalized headers. A terminal signature under
//! the checkpoint's own committee is not a trust root.
use crate::db::{CheckpointImport, FinalizerState};
use anyhow::{Result, bail, ensure};
use commonware_codec::Encode;
use commonware_cryptography::bls12381::primitives::variant::{MinPk, Variant};
use commonware_parallel::Sequential;
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use commonware_utils::{TryCollect, ordered::BiMap, sys_rng};
use summit_types::{
    Block, EngineClient, FinalizedHeader, PublicKey, chain_domain, checkpoint::Checkpoint,
    consensus_state::ConsensusState, scheme::MultisigScheme,
};
use tracing::{info, warn};

type Import = CheckpointImport<MinPk>;

/// Check all overlapping finalized epochs, not just the supplied terminal.
/// Certificate bytes may differ for a same-digest later-view reproposal.
pub async fn check_history<E: BufferPooler + Clock + Metrics + Storage>(
    db: &FinalizerState<E, MinPk>,
    headers: &[FinalizedHeader<MultisigScheme>],
) -> Result<()> {
    let imported = db.get_checkpoint_import().await?;
    let pending = db.get_pending_import().await?.map(|(_, record)| record);
    for header in headers {
        if let Some(local) = db.get_finalized_header(header.header().epoch()).await {
            ensure!(
                local.header().computed_digest() == header.header().computed_digest(),
                "checkpoint conflicts with local finalized history"
            );
        }
        if let Some(previous) = header.header().epoch().checked_sub(1)
            && let Some(local) = db.get_finalized_header(previous).await
        {
            ensure!(
                header.header().prev_epoch_header_hash() == local.header().computed_digest(),
                "checkpoint does not extend local finalized history"
            );
        }
        for local in imported.iter().chain(pending.iter()) {
            if local.finalized_header.header().epoch() == header.header().epoch() {
                ensure!(
                    local.finalized_header.header().computed_digest()
                        == header.header().computed_digest(),
                    "checkpoint conflicts with imported history"
                );
            } else if local.finalized_header.header().epoch().checked_add(1)
                == Some(header.header().epoch())
            {
                ensure!(
                    header.header().prev_epoch_header_hash()
                        == local.finalized_header.header().computed_digest(),
                    "checkpoint does not extend imported history"
                );
            }
        }
    }
    db.ensure_healthy()
}

fn validate_candidate(
    state: ConsensusState,
    header: FinalizedHeader<MultisigScheme>,
    last_block: Option<Block>,
    config_digest: [u8; 32],
) -> Result<(ConsensusState, Import)> {
    // Production restores the pending-checkpoint and captured proof fields;
    // internal callers can also supply the raw decoded checkpoint state.
    let raw = state
        .get_pending_checkpoint()
        .cloned()
        .unwrap_or_else(|| Checkpoint::new(&state));
    let decoded = ConsensusState::try_from(&raw)?;
    let mut restored = decoded.clone();
    restored.set_pending_checkpoint(Some(raw.clone()));
    restored.capture_state_root(restored.get_latest_height());
    ensure!(
        state.encode() == decoded.encode() || state.encode() == restored.encode(),
        "checkpoint state differs from its authenticated snapshot"
    );
    let height = restored.get_latest_height();
    ensure!(
        height.checked_add(1) == Some(header.header().height()),
        "checkpoint terminal is not the state's successor"
    );
    ensure!(
        summit_types::utils::is_last_block_of_epoch(
            restored.get_epocher(),
            header.header().height()
        ),
        "checkpoint anchor is not epoch-terminal"
    );
    ensure!(
        header.header().epoch() == restored.get_epoch(),
        "checkpoint epoch mismatch"
    );
    ensure!(
        header.header().parent() == restored.get_head_digest(),
        "checkpoint parent mismatch"
    );
    ensure!(
        header.header().checkpoint_hash() == raw.digest,
        "checkpoint hash mismatch"
    );
    ensure!(
        header.header().computed_digest() == header.finalization().proposal.payload,
        "checkpoint header/certificate mismatch"
    );
    ensure!(
        header.finalization().proposal.round.epoch().get() == restored.get_epoch()
            && header.finalization().proposal.round.view().get() >= header.header().view(),
        "checkpoint certificate round mismatch"
    );
    let participants: BiMap<PublicKey, <MinPk as Variant>::Public> = restored
        .get_current_epoch_validators()
        .into_iter()
        .map(|(node, key)| {
            let key: &<MinPk as Variant>::Public = key.as_ref();
            (node, *key)
        })
        .try_collect()
        .map_err(|e| anyhow::anyhow!("invalid checkpoint committee: {e:?}"))?;
    let scheme = MultisigScheme::verifier(&chain_domain(config_digest), participants);
    ensure!(
        header
            .finalization()
            .verify(&mut sys_rng(), &scheme, &Sequential),
        "checkpoint terminal signature verification failed"
    );
    if let Some(block) = &last_block {
        ensure!(
            block.digest() == header.finalization().proposal.payload,
            "checkpoint last_block mismatch"
        );
        Block::new_with_verify(
            block.header.clone(),
            block.payload.clone(),
            block.execution_requests.clone(),
        )?;
    }
    Ok((
        restored,
        Import {
            processed_height: height,
            config_digest,
            finalized_header: header,
            last_block,
        },
    ))
}

async fn finish_import<E: BufferPooler + Clock + Metrics + Storage, C: EngineClient>(
    db: &mut FinalizerState<E, MinPk>,
    client: &mut C,
    state: &ConsensusState,
    record: Import,
) -> Result<()> {
    // Pending state is already durable. A transport error may mean Reth applied
    // forkchoice but its response was lost: retain the record for restart/retry.
    let status = client.commit_hash(*state.get_forkchoice()).await?;
    if !status.is_valid() && !status.is_syncing() {
        db.discard_pending_import().await?;
        bail!("execution client rejected checkpoint: {status:?}");
    }
    if status.is_syncing() {
        warn!(
            "checkpoint execution head is SYNCING, not yet validated; normal execution retries remain required"
        );
    }
    db.import_checkpoint(state, record).await
}

/// Select and durably prepare startup. Only the returned import record authorizes
/// an application skip. Never infer an import from an ordinary finalizer height.
#[allow(clippy::too_many_arguments)]
pub async fn prepare<E: BufferPooler + Clock + Metrics + Storage, C: EngineClient>(
    db: &mut FinalizerState<E, MinPk>,
    client: &mut C,
    initial: ConsensusState,
    header: Option<FinalizedHeader<MultisigScheme>>,
    last_block: Option<Block>,
    config_digest: [u8; 32],
) -> Result<(ConsensusState, Option<Import>)> {
    // Validate supplied artifacts even if they turn out to be older than storage.
    let candidate = match header {
        Some(header) => Some(validate_candidate(
            initial.clone(),
            header,
            last_block,
            config_digest,
        )?),
        None => {
            ensure!(
                last_block.is_none(),
                "checkpoint last_block requires a verified terminal header"
            );
            None
        }
    };
    if let Some((_, record)) = &candidate {
        check_history(db, std::slice::from_ref(&record.finalized_header)).await?;
    }
    let mut execution_checked = false;
    let mut stored = db.get_latest_consensus_state().await;
    let mut imported = db.get_checkpoint_import().await?;
    db.ensure_healthy()?;
    if let Some(record) = &imported {
        ensure!(
            record.config_digest == config_digest,
            "stored checkpoint belongs to a different chain"
        );
        ensure!(
            stored
                .as_ref()
                .is_some_and(|s| s.get_latest_height() >= record.processed_height),
            "import authorization has no backing state"
        );
    }
    if let Some((pending, record)) = db.get_pending_import().await? {
        ensure!(
            record.config_digest == config_digest,
            "pending checkpoint belongs to a different chain"
        );
        ensure!(
            pending.get_latest_height() == record.processed_height,
            "pending import height mismatch"
        );
        ensure!(
            stored
                .as_ref()
                .is_none_or(|s| s.get_latest_height() <= record.processed_height),
            "pending import is behind durable state"
        );
        let (pending, record) = validate_candidate(
            pending,
            record.finalized_header,
            record.last_block,
            config_digest,
        )?;
        if let Some((_, candidate)) = &candidate
            && candidate.processed_height == record.processed_height
        {
            ensure!(
                candidate.finalized_header.header().computed_digest()
                    == record.finalized_header.header().computed_digest(),
                "checkpoint conflicts with pending import"
            );
        }
        finish_import(db, client, &pending, record.clone()).await?;
        execution_checked = true;
        stored = Some(pending);
        imported = Some(record);
    }
    if let Some((candidate, record)) = candidate {
        let height = candidate.get_latest_height();
        match stored.as_ref() {
            Some(local) if local.get_latest_height() > height => {
                warn!(
                    checkpoint_height = height,
                    stored_height = local.get_latest_height(),
                    "ignoring older checkpoint without rollback"
                );
            }
            Some(local) if local.get_latest_height() == height => {
                ensure!(
                    local.get_head_digest() == candidate.get_head_digest()
                        && local.ssz_tree().root() == candidate.ssz_tree().root(),
                    "checkpoint conflicts with state at the same height"
                );
                // A matching checkpoint can authorize a skip even if this height
                // was originally reached through normal block execution.
                if imported
                    .as_ref()
                    .is_none_or(|old| old.processed_height < height)
                {
                    db.stage_checkpoint_import(&candidate, &record).await?;
                    finish_import(db, client, &candidate, record.clone()).await?;
                    execution_checked = true;
                    imported = Some(record);
                    stored = Some(candidate);
                }
            }
            _ => {
                db.stage_checkpoint_import(&candidate, &record).await?;
                finish_import(db, client, &candidate, record.clone()).await?;
                execution_checked = true;
                info!(height, "checkpoint state and skip authorization committed");
                imported = Some(record);
                stored = Some(candidate);
            }
        }
    } else if let Some(local) = &stored {
        ensure!(
            initial.get_latest_height() <= local.get_latest_height(),
            "newer initial state requires a verified checkpoint"
        );
    }
    let state = stored.unwrap_or(initial);
    // Also validate the current execution head before handing a recovered import
    // authorization to the syncer. Explicit INVALID never permits startup.
    if imported.is_some() && !execution_checked {
        let status = client.commit_hash(*state.get_forkchoice()).await?;
        ensure!(
            status.is_valid() || status.is_syncing(),
            "execution client rejected recovered checkpoint state: {status:?}"
        );
    }
    db.ensure_healthy()?;
    Ok((state, imported))
}
