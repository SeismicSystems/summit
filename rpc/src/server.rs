#[cfg(feature = "permissioned")]
use crate::api::SummitPermissionedApiServer;
use crate::api::{SummitAdminApiServer, SummitApiServer, SummitProofApiServer};
#[cfg(feature = "permissioned")]
use crate::auth;
use crate::error::RpcError;
use crate::types::{
    CheckpointInfoRes, CheckpointRes, DepositResponse, DepositTransactionResponse,
    EpochBoundsResponse, FinalizedHeaderDigestRes, FinalizedHeaderRes, PendingWithdrawalResponse,
    PublicKeysResponse, StateProofResponse, StateProofResult, StateRootResponse,
    ValidatorAccountResponse,
};
use alloy_primitives::{Address, U256, hex::FromHex as _};
use async_trait::async_trait;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::Signer;
use commonware_formatting::from_hex;
use jsonrpsee::core::RpcResult;
use ssz::Encode as _;
use std::sync::Arc;
#[cfg(feature = "permissioned")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use summit_types::consensus_state_query::ConsensusStateQuery;
#[cfg(feature = "permissioned")]
use summit_types::pause_signature_domain;
use summit_types::scheme::MultisigScheme;
use summit_types::ssz_tree_key::SszStateKey;
use summit_types::{
    Digest, KeyPaths, PublicKey, deposit_signature_domain,
    execution_request::{DepositRequest, compute_deposit_data_root},
};

const MAX_STATE_PROOF_KEYS: usize = 128;
const MAX_STATE_PROOF_COST: usize = 512;
/// Maximum number of state-proof generations allowed to be in flight at once.
/// Each accepted request spawns an off-loop proof task in the finalizer; this
/// caps how many run concurrently so a flood of individually limit-respecting
/// requests cannot just move the pressure onto the shared task pool. At capacity
/// further requests are rejected (retryable) rather than queued, keeping task
/// count and memory bounded under load.
pub const MAX_CONCURRENT_STATE_PROOFS: usize = 16;

#[derive(Clone)]
pub struct SummitRpcServer {
    key_store_path: String,
    state_query: ConsensusStateQuery<MultisigScheme>,
    deposit_signature_domain: Digest,
    /// The derived child public key (hex) used as the live P2P identity when
    /// the node runs with `--observer`; `None` on validator nodes. Observers
    /// report this key instead of the master keystore identity and must not
    /// sign with the validator keystore, so keystore-signing methods are
    /// disabled when this is set.
    observer_node_key: Option<String>,
    /// Count of in-flight state-proof generations, shared across all cloned
    /// handler instances so the cap is global to the server.
    in_flight_state_proofs: Arc<AtomicUsize>,
    #[cfg(feature = "permissioned")]
    paused: Arc<AtomicBool>,
    /// Hex of the pause-authorization domain (genesis hash + namespace). Bound
    /// into every pause/unpause signed message so an authorization for one
    /// deployment cannot be replayed against another that trusts the same
    /// admin key.
    #[cfg(feature = "permissioned")]
    pause_scope: String,
}

/// Releases one in-flight state-proof slot on drop — covers normal completion,
/// early return, and future cancellation alike.
struct StateProofSlot(Arc<AtomicUsize>);

impl Drop for StateProofSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl SummitRpcServer {
    pub fn new(
        key_store_path: String,
        state_query: ConsensusStateQuery<MultisigScheme>,
        genesis_hash: [u8; 32],
        namespace: &[u8],
        observer_node_key: Option<String>,
        #[cfg(feature = "permissioned")] paused: Arc<AtomicBool>,
    ) -> Self {
        Self {
            key_store_path,
            state_query,
            deposit_signature_domain: deposit_signature_domain(genesis_hash, namespace),
            observer_node_key,
            in_flight_state_proofs: Arc::new(AtomicUsize::new(0)),
            #[cfg(feature = "permissioned")]
            paused,
            #[cfg(feature = "permissioned")]
            pause_scope: alloy_primitives::hex::encode(pause_signature_domain(
                genesis_hash,
                namespace,
            )),
        }
    }
}

fn state_proof_key_cost(key: &SszStateKey) -> usize {
    match key {
        SszStateKey::Scalar(_) => 1,
        SszStateKey::Validator(_)
        | SszStateKey::Deposit(_)
        | SszStateKey::Withdrawal(_)
        | SszStateKey::ProtocolParam(_)
        | SszStateKey::AddedValidator(_)
        | SszStateKey::RemovedValidator(_) => 4,
        SszStateKey::ValidatorField(_, _)
        | SszStateKey::DepositField(_, _)
        | SszStateKey::WithdrawalField(_, _)
        | SszStateKey::ProtocolParamField(_, _)
        | SszStateKey::AddedValidatorField(_, _) => 8,
    }
}

#[async_trait]
impl SummitApiServer for SummitRpcServer {
    async fn health(&self) -> RpcResult<String> {
        Ok("Ok".to_string())
    }

    async fn get_public_keys(&self) -> RpcResult<PublicKeysResponse> {
        // An observer's live P2P identity is the derived child key and it
        // never acts as a consensus participant; report that key with no
        // consensus key rather than the validator master identity.
        if let Some(observer_node_key) = &self.observer_node_key {
            return Ok(PublicKeysResponse {
                node: observer_node_key.clone(),
                consensus: String::new(),
            });
        }

        let key_paths = KeyPaths::new(self.key_store_path.clone());

        let node = key_paths.node_public_key().map_err(|e| {
            RpcError::KeyStoreError(format!("Failed to read node public key: {}", e))
        })?;

        let consensus = key_paths.consensus_public_key().map_err(|e| {
            RpcError::KeyStoreError(format!("Failed to read consensus public key: {}", e))
        })?;

        Ok(PublicKeysResponse { node, consensus })
    }

    async fn get_checkpoint(&self, epoch: u64) -> RpcResult<CheckpointRes> {
        let maybe_checkpoint = self.state_query.clone().get_checkpoint(epoch).await;

        let Some((checkpoint, last_block)) = maybe_checkpoint else {
            return Err(RpcError::CheckpointNotFound.into());
        };

        // try to get the finalized header for this epoch
        let maybe_header = self.state_query.clone().get_finalized_header(epoch).await;

        let Some(header) = maybe_header else {
            return Err(RpcError::CheckpointNotFound.into());
        };

        Ok(CheckpointRes {
            digest: checkpoint.digest.0,
            epoch,
            checkpoint: checkpoint.as_ssz_bytes(),
            last_block: last_block.as_ssz_bytes(),
            finalized_header: header.as_ssz_bytes(),
        })
    }

    async fn get_latest_checkpoint(&self) -> RpcResult<CheckpointRes> {
        let maybe_checkpoint = self.state_query.clone().get_latest_checkpoint().await;

        let (Some((checkpoint, last_block)), epoch) = maybe_checkpoint else {
            return Err(RpcError::CheckpointNotFound.into());
        };

        // try to get the finalized header for this epoch
        let maybe_header = self.state_query.clone().get_finalized_header(epoch).await;

        let Some(header) = maybe_header else {
            return Err(RpcError::CheckpointNotFound.into());
        };

        Ok(CheckpointRes {
            digest: checkpoint.digest.0,
            epoch,
            checkpoint: checkpoint.as_ssz_bytes(),
            last_block: last_block.as_ssz_bytes(),
            finalized_header: header.as_ssz_bytes(),
        })
    }

    async fn get_latest_checkpoint_info(&self) -> RpcResult<CheckpointInfoRes> {
        let maybe_checkpoint = self.state_query.clone().get_latest_checkpoint().await;

        let (Some((checkpoint, _)), epoch) = maybe_checkpoint else {
            return Err(RpcError::CheckpointNotFound.into());
        };

        Ok(CheckpointInfoRes {
            epoch,
            digest: checkpoint.digest.0,
        })
    }

    async fn get_finalized_header(&self, epoch: u64) -> RpcResult<FinalizedHeaderRes> {
        let maybe_header = self.state_query.clone().get_finalized_header(epoch).await;

        let Some(header) = maybe_header else {
            return Err(RpcError::FinalizedHeaderNotFound.into());
        };

        Ok(FinalizedHeaderRes {
            epoch,
            finalized_header: header.as_ssz_bytes(),
        })
    }

    async fn get_finalized_header_digest(&self, epoch: u64) -> RpcResult<FinalizedHeaderDigestRes> {
        let maybe_header = self.state_query.clone().get_finalized_header(epoch).await;

        let Some(header) = maybe_header else {
            return Err(RpcError::FinalizedHeaderNotFound.into());
        };

        Ok(FinalizedHeaderDigestRes {
            epoch,
            digest: header.header().get_digest().0,
        })
    }

    async fn get_latest_height(&self) -> RpcResult<u64> {
        let height = self.state_query.get_latest_height().await;
        Ok(height)
    }

    async fn get_latest_epoch(&self) -> RpcResult<u64> {
        let epoch = self.state_query.get_latest_epoch().await;
        Ok(epoch)
    }

    async fn get_validator_balance(&self, public_key: String) -> RpcResult<u64> {
        let key_bytes = from_hex(&public_key)
            .ok_or_else(|| RpcError::InvalidPublicKey("Invalid hex format".to_string()))?;

        let public_key = PublicKey::decode(&*key_bytes)
            .map_err(|_| RpcError::InvalidPublicKey("Unable to decode public key".to_string()))?;

        let balance = self.state_query.get_validator_balance(public_key).await;

        match balance {
            Some(balance) => Ok(balance),
            None => Err(RpcError::ValidatorNotFound.into()),
        }
    }

    async fn get_validator_account(
        &self,
        public_key: String,
    ) -> RpcResult<ValidatorAccountResponse> {
        let key_bytes = from_hex(&public_key)
            .ok_or_else(|| RpcError::InvalidPublicKey("Invalid hex format".to_string()))?;

        let public_key = PublicKey::decode(&*key_bytes)
            .map_err(|_| RpcError::InvalidPublicKey("Unable to decode public key".to_string()))?;

        let account = self.state_query.get_validator_account(public_key).await;

        match account {
            Some(a) => Ok(ValidatorAccountResponse {
                consensus_public_key: AsRef::<[u8]>::as_ref(&a.consensus_public_key).to_vec(),
                withdrawal_credentials: a.withdrawal_credentials.0.0,
                balance: a.balance,
                status: format!("{:?}", a.status),
                joining_epoch: a.joining_epoch,
                last_deposit_index: a.last_deposit_index,
            }),
            None => Err(RpcError::ValidatorNotFound.into()),
        }
    }

    async fn get_minimum_stake(&self) -> RpcResult<u64> {
        let minimum_stake = self.state_query.get_minimum_stake().await;
        Ok(minimum_stake)
    }

    async fn get_epoch_length(&self) -> RpcResult<u64> {
        let epoch_length = self.state_query.get_epoch_length().await;
        Ok(epoch_length)
    }

    async fn get_allowed_timestamp_future(&self) -> RpcResult<u64> {
        let ms = self.state_query.get_allowed_timestamp_future().await;
        Ok(ms)
    }

    async fn get_treasury_address(&self) -> RpcResult<String> {
        let address = self.state_query.get_treasury_address().await;
        Ok(address.to_string())
    }

    async fn get_epoch_bounds(&self, epoch: u64) -> RpcResult<EpochBoundsResponse> {
        let bounds = self.state_query.get_epoch_bounds(epoch).await;
        match bounds {
            Some((first_height, last_height)) => Ok(EpochBoundsResponse {
                first_height,
                last_height,
            }),
            None => Err(RpcError::EpochNotFound.into()),
        }
    }

    async fn get_deposit(&self, index: usize) -> RpcResult<DepositResponse> {
        let deposit = self.state_query.get_deposit(index).await;
        match deposit {
            Some(d) => Ok(DepositResponse {
                node_pubkey: d
                    .node_pubkey
                    .as_ref()
                    .try_into()
                    .expect("ed25519 key is 32 bytes"),
                consensus_pubkey: AsRef::<[u8]>::as_ref(&d.consensus_pubkey).to_vec(),
                withdrawal_credentials: d.withdrawal_credentials,
                amount: d.amount,
                node_signature: d.node_signature.to_vec(),
                consensus_signature: d.consensus_signature.to_vec(),
                index: d.index,
            }),
            None => Err(RpcError::DepositNotFound.into()),
        }
    }

    async fn get_deposit_count(&self) -> RpcResult<usize> {
        let count = self.state_query.get_deposit_count().await;
        Ok(count)
    }

    async fn get_pending_withdrawal(
        &self,
        public_key: String,
    ) -> RpcResult<PendingWithdrawalResponse> {
        let key_bytes = from_hex(&public_key)
            .ok_or_else(|| RpcError::InvalidPublicKey("Invalid hex format".to_string()))?;

        let pubkey: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| RpcError::InvalidPublicKey("pubkey must be 32 bytes".to_string()))?;

        let withdrawal = self.state_query.get_withdrawal(pubkey).await;
        match withdrawal {
            Some(w) => Ok(PendingWithdrawalResponse {
                withdrawal_index: w.inner.index,
                validator_index: w.inner.validator_index,
                address: w.inner.address.0.0,
                amount: w.inner.amount,
                pubkey: w.pubkey,
                epoch: w.epoch,
            }),
            None => Err(RpcError::WithdrawalNotFound.into()),
        }
    }
}

#[async_trait]
impl SummitAdminApiServer for SummitRpcServer {
    async fn get_deposit_signature(
        &self,
        amount: u64,
        address: String,
    ) -> RpcResult<DepositTransactionResponse> {
        // An observer's live P2P identity is a derived child key, not the
        // master node key this method would sign for — refuse rather than
        // produce a deposit binding the master validator identity.
        if self.observer_node_key.is_some() {
            return Err(RpcError::DisabledInObserverMode.into());
        }

        let mut withdrawal_credentials = [0u8; 32];
        withdrawal_credentials[0] = 0x01;

        let withdrawal_address = Address::from_hex(address)
            .map_err(|e| RpcError::InvalidPublicKey(format!("Invalid address: {}", e)))?;
        withdrawal_credentials[12..32].copy_from_slice(withdrawal_address.as_slice());

        let key_paths = KeyPaths::new(self.key_store_path.clone());

        let consensus_priv_key = key_paths
            .consensus_private_key()
            .map_err(|e| RpcError::KeyStoreError(format!("Failed to read consensus key: {}", e)))?;
        let consensus_pub = consensus_priv_key.public_key();

        let node_priv_key = key_paths
            .node_private_key()
            .map_err(|e| RpcError::KeyStoreError(format!("Failed to read node key: {}", e)))?;
        let node_pub = node_priv_key.public_key();

        let req = DepositRequest {
            node_pubkey: node_pub.clone(),
            consensus_pubkey: consensus_pub.clone(),
            withdrawal_credentials,
            amount,
            node_signature: [0; 64],
            consensus_signature: [0; 96],
            index: 0,
        };

        let message = req.as_message(self.deposit_signature_domain);

        let node_signature = node_priv_key.sign(&[], &message);
        let node_signature_bytes: [u8; 64] = node_signature
            .as_ref()
            .try_into()
            .expect("ed25519 sig is always 64 bytes");

        let consensus_signature = consensus_priv_key.sign(&[], &message);
        let consensus_signature_slice: &[u8] = consensus_signature.as_ref();
        let consensus_signature_bytes: [u8; 96] = consensus_signature_slice
            .try_into()
            .expect("bls sig is always 96 bytes");

        let node_pubkey_bytes: [u8; 32] = node_pub.to_vec().try_into().expect("Cannot fail");
        let consensus_pubkey_bytes: [u8; 48] =
            consensus_pub.encode().as_ref()[..48].try_into().unwrap();

        let deposit_amount = U256::from(amount) * U256::from(1_000_000_000u64);

        let deposit_root = compute_deposit_data_root(
            &node_pubkey_bytes,
            &consensus_pubkey_bytes,
            &withdrawal_credentials,
            deposit_amount,
            &node_signature_bytes,
            &consensus_signature_bytes,
        );

        Ok(DepositTransactionResponse {
            node_pubkey: node_pubkey_bytes,
            consensus_pubkey: consensus_pubkey_bytes.to_vec(),
            withdrawal_credentials,
            node_signature: node_signature_bytes.to_vec(),
            consensus_signature: consensus_signature_bytes.to_vec(),
            deposit_data_root: deposit_root,
        })
    }
}

#[cfg(feature = "permissioned")]
#[async_trait]
impl SummitPermissionedApiServer for SummitRpcServer {
    async fn pause(&self, timestamp_secs: u64, signature: String) -> RpcResult<bool> {
        auth::verify_action(
            &self.pause_scope,
            auth::ACTION_PAUSE,
            timestamp_secs,
            &signature,
        )?;
        self.paused.store(true, Ordering::Relaxed);
        tracing::info!("consensus paused via RPC");
        Ok(true)
    }

    async fn unpause(&self, timestamp_secs: u64, signature: String) -> RpcResult<bool> {
        auth::verify_action(
            &self.pause_scope,
            auth::ACTION_UNPAUSE,
            timestamp_secs,
            &signature,
        )?;
        self.paused.store(false, Ordering::Relaxed);
        tracing::info!("consensus unpaused via RPC");
        Ok(true)
    }

    async fn is_paused(&self) -> RpcResult<bool> {
        Ok(self.paused.load(Ordering::Relaxed))
    }
}

#[async_trait]
impl SummitProofApiServer for SummitRpcServer {
    async fn get_state_root(&self) -> RpcResult<StateRootResponse> {
        let (root, el_block_number) = self.state_query.get_state_root().await;
        Ok(StateRootResponse {
            root,
            el_block_number,
        })
    }

    async fn get_state_proof(&self, keys: Vec<String>) -> RpcResult<StateProofResponse> {
        if keys.len() > MAX_STATE_PROOF_KEYS {
            return Err(RpcError::StateProofKeyLimit {
                max: MAX_STATE_PROOF_KEYS,
                actual: keys.len(),
            }
            .into());
        }

        let parsed_keys = keys
            .iter()
            .map(|k| summit_types::ssz_tree_key::parse_key(k).map_err(RpcError::InvalidKey))
            .collect::<Result<Vec<_>, _>>()?;

        let cost = parsed_keys.iter().map(state_proof_key_cost).sum::<usize>();
        if cost > MAX_STATE_PROOF_COST {
            return Err(RpcError::StateProofCostLimit {
                max: MAX_STATE_PROOF_COST,
                actual: cost,
            }
            .into());
        }

        // Bound concurrent proof generation. The per-request key/cost limits cap
        // each request, but without this a remote caller could still flood the
        // node with accepted requests and pile up off-loop proof tasks on the
        // shared pool. Acquire a slot or reject (retryable), never queue, so
        // task count and memory stay bounded under load.
        if self
            .in_flight_state_proofs
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_CONCURRENT_STATE_PROOFS).then_some(n + 1)
            })
            .is_err()
        {
            return Err(RpcError::StateProofBusy {
                max: MAX_CONCURRENT_STATE_PROOFS,
            }
            .into());
        }
        // Hand the slot guard to the proof task rather than holding it on this
        // handler future. Acquisition stays here so a flood is rejected at
        // admission, but ownership travels through the query channel into the
        // finalizer's detached proof task, which drops it only once generation
        // finishes. That keeps the in-flight count tied to real proof work: if
        // the client disconnects (or this future is cancelled) after the task
        // is spawned, the slot must not be freed while the work is still
        // running.
        let slot = StateProofSlot(Arc::clone(&self.in_flight_state_proofs));

        let requested_len = keys.len();
        let (root, el_block_number, proofs) = self
            .state_query
            .generate_state_proof(parsed_keys, Box::new(slot))
            .await;
        // Preserve one-result-per-requested-key alignment (#260/#267): the
        // off-loop generator returns a positional `Vec<Option<SszProof>>`, so a
        // missing key must surface as an error slot, never be dropped.
        if proofs.len() != requested_len {
            return Err(RpcError::Internal(format!(
                "state proof response length mismatch: requested {requested_len}, got {}",
                proofs.len()
            ))
            .into());
        }

        let results = keys
            .into_iter()
            .zip(proofs)
            .map(|(key, entry)| {
                let error = entry
                    .is_none()
                    .then(|| "key is absent or out of range".to_string());
                let (proof, key_proof) = match entry {
                    Some(e) => (Some(e.field), e.key),
                    None => (None, None),
                };
                StateProofResult {
                    key,
                    proof,
                    key_proof,
                    error,
                }
            })
            .collect();

        Ok(StateProofResponse {
            root,
            el_block_number,
            results,
        })
    }
}
