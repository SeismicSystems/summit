#[cfg(feature = "permissioned")]
use crate::api::SummitPermissionedApiServer;
use crate::api::{SummitApiServer, SummitProofApiServer};
use crate::error::RpcError;
use crate::types::{
    CheckpointInfoRes, CheckpointRes, DepositResponse, DepositTransactionResponse,
    EpochBoundsResponse, FinalizedHeaderRes, PendingWithdrawalResponse, PublicKeysResponse,
    StateProofResponse, StateRootResponse, ValidatorAccountResponse,
};
use alloy_primitives::{Address, U256, hex::FromHex as _};
use async_trait::async_trait;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{Hasher as _, Sha256, Signer};
use commonware_utils::from_hex_formatted;
use jsonrpsee::core::RpcResult;
use ssz::Encode as _;
#[cfg(feature = "permissioned")]
use std::sync::Arc;
#[cfg(feature = "permissioned")]
use std::sync::atomic::{AtomicBool, Ordering};
use summit_finalizer::FinalizerMailbox;
use summit_types::Block;
use summit_types::scheme::MultisigScheme;
use summit_types::{
    KeyPaths, PROTOCOL_VERSION, PublicKey,
    execution_request::{DepositRequest, compute_deposit_data_root},
};

#[derive(Clone)]
pub struct SummitRpcServer {
    key_store_path: String,
    finalizer_mailbox: FinalizerMailbox<MultisigScheme, Block>,
    #[cfg(feature = "permissioned")]
    paused: Arc<AtomicBool>,
}

impl SummitRpcServer {
    pub fn new(
        key_store_path: String,
        finalizer_mailbox: FinalizerMailbox<MultisigScheme, Block>,
        #[cfg(feature = "permissioned")] paused: Arc<AtomicBool>,
    ) -> Self {
        Self {
            key_store_path,
            finalizer_mailbox,
            #[cfg(feature = "permissioned")]
            paused,
        }
    }
}

#[async_trait]
impl SummitApiServer for SummitRpcServer {
    async fn health(&self) -> RpcResult<String> {
        Ok("Ok".to_string())
    }

    async fn get_public_keys(&self) -> RpcResult<PublicKeysResponse> {
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
        let maybe_checkpoint = self.finalizer_mailbox.clone().get_checkpoint(epoch).await;

        let Some((checkpoint, last_block)) = maybe_checkpoint else {
            return Err(RpcError::CheckpointNotFound.into());
        };

        // try to get the finalized header for this epoch
        let maybe_header = self
            .finalizer_mailbox
            .clone()
            .get_finalized_header(epoch)
            .await;

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
        let maybe_checkpoint = self.finalizer_mailbox.clone().get_latest_checkpoint().await;

        let (Some((checkpoint, last_block)), epoch) = maybe_checkpoint else {
            return Err(RpcError::CheckpointNotFound.into());
        };

        // try to get the finalized header for this epoch
        let maybe_header = self
            .finalizer_mailbox
            .clone()
            .get_finalized_header(epoch)
            .await;

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
        let maybe_checkpoint = self.finalizer_mailbox.clone().get_latest_checkpoint().await;

        let (Some((checkpoint, _)), epoch) = maybe_checkpoint else {
            return Err(RpcError::CheckpointNotFound.into());
        };

        Ok(CheckpointInfoRes {
            epoch,
            digest: checkpoint.digest.0,
        })
    }

    async fn get_finalized_header(&self, epoch: u64) -> RpcResult<FinalizedHeaderRes> {
        let maybe_header = self
            .finalizer_mailbox
            .clone()
            .get_finalized_header(epoch)
            .await;

        let Some(header) = maybe_header else {
            return Err(RpcError::FinalizedHeaderNotFound.into());
        };

        Ok(FinalizedHeaderRes {
            epoch,
            finalized_header: header.as_ssz_bytes(),
        })
    }

    async fn get_latest_height(&self) -> RpcResult<u64> {
        let height = self.finalizer_mailbox.get_latest_height().await;
        Ok(height)
    }

    async fn get_latest_epoch(&self) -> RpcResult<u64> {
        let epoch = self.finalizer_mailbox.get_latest_epoch().await;
        Ok(epoch)
    }

    async fn get_validator_balance(&self, public_key: String) -> RpcResult<u64> {
        let key_bytes = from_hex_formatted(&public_key)
            .ok_or_else(|| RpcError::InvalidPublicKey("Invalid hex format".to_string()))?;

        let public_key = PublicKey::decode(&*key_bytes)
            .map_err(|_| RpcError::InvalidPublicKey("Unable to decode public key".to_string()))?;

        let balance = self
            .finalizer_mailbox
            .get_validator_balance(public_key)
            .await;

        match balance {
            Some(balance) => Ok(balance),
            None => Err(RpcError::ValidatorNotFound.into()),
        }
    }

    async fn get_validator_account(
        &self,
        public_key: String,
    ) -> RpcResult<ValidatorAccountResponse> {
        let key_bytes = from_hex_formatted(&public_key)
            .ok_or_else(|| RpcError::InvalidPublicKey("Invalid hex format".to_string()))?;

        let public_key = PublicKey::decode(&*key_bytes)
            .map_err(|_| RpcError::InvalidPublicKey("Unable to decode public key".to_string()))?;

        let account = self
            .finalizer_mailbox
            .get_validator_account(public_key)
            .await;

        match account {
            Some(a) => Ok(ValidatorAccountResponse {
                consensus_public_key: AsRef::<[u8]>::as_ref(&a.consensus_public_key).to_vec(),
                withdrawal_credentials: a.withdrawal_credentials.0.0,
                balance: a.balance,
                status: format!("{:?}", a.status),
                has_pending_deposit: a.has_pending_deposit,
                has_pending_withdrawal: a.has_pending_withdrawal,
                joining_epoch: a.joining_epoch,
                last_deposit_index: a.last_deposit_index,
            }),
            None => Err(RpcError::ValidatorNotFound.into()),
        }
    }

    async fn get_deposit_signature(
        &self,
        amount: u64,
        address: String,
    ) -> RpcResult<DepositTransactionResponse> {
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

        let protocol_version_digest = Sha256::hash(&PROTOCOL_VERSION.to_le_bytes());
        let message = req.as_message(protocol_version_digest);

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

    async fn get_minimum_stake(&self) -> RpcResult<u64> {
        let minimum_stake = self.finalizer_mailbox.get_minimum_stake().await;
        Ok(minimum_stake)
    }

    async fn get_maximum_stake(&self) -> RpcResult<u64> {
        let maximum_stake = self.finalizer_mailbox.get_maximum_stake().await;
        Ok(maximum_stake)
    }

    async fn get_epoch_length(&self) -> RpcResult<u64> {
        let epoch_length = self.finalizer_mailbox.get_epoch_length().await;
        Ok(epoch_length)
    }

    async fn get_allowed_timestamp_future(&self) -> RpcResult<u64> {
        let ms = self.finalizer_mailbox.get_allowed_timestamp_future().await;
        Ok(ms)
    }

    async fn get_treasury_address(&self) -> RpcResult<String> {
        let address = self.finalizer_mailbox.get_treasury_address().await;
        Ok(address.to_string())
    }

    async fn get_epoch_bounds(&self, epoch: u64) -> RpcResult<EpochBoundsResponse> {
        let bounds = self.finalizer_mailbox.get_epoch_bounds(epoch).await;
        match bounds {
            Some((first_height, last_height)) => Ok(EpochBoundsResponse {
                first_height,
                last_height,
            }),
            None => Err(RpcError::EpochNotFound.into()),
        }
    }

    async fn get_deposit(&self, index: usize) -> RpcResult<DepositResponse> {
        let deposit = self.finalizer_mailbox.get_deposit(index).await;
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
        let count = self.finalizer_mailbox.get_deposit_count().await;
        Ok(count)
    }

    async fn get_pending_withdrawal(
        &self,
        public_key: String,
    ) -> RpcResult<PendingWithdrawalResponse> {
        let key_bytes = from_hex_formatted(&public_key)
            .ok_or_else(|| RpcError::InvalidPublicKey("Invalid hex format".to_string()))?;

        let pubkey: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| RpcError::InvalidPublicKey("pubkey must be 32 bytes".to_string()))?;

        let withdrawal = self.finalizer_mailbox.get_withdrawal(pubkey).await;
        match withdrawal {
            Some(w) => Ok(PendingWithdrawalResponse {
                withdrawal_index: w.inner.index,
                validator_index: w.inner.validator_index,
                address: w.inner.address.0.0,
                amount: w.inner.amount,
                pubkey: w.pubkey,
                balance_deduction: w.balance_deduction,
                epoch: w.epoch,
            }),
            None => Err(RpcError::WithdrawalNotFound.into()),
        }
    }
}

#[cfg(feature = "permissioned")]
#[async_trait]
impl SummitPermissionedApiServer for SummitRpcServer {
    async fn pause(&self) -> RpcResult<bool> {
        self.paused.store(true, Ordering::Relaxed);
        tracing::info!("consensus paused via RPC");
        Ok(true)
    }

    async fn unpause(&self) -> RpcResult<bool> {
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
        let (root, el_block_number) = self.finalizer_mailbox.get_state_root().await;
        Ok(StateRootResponse {
            root,
            el_block_number,
        })
    }

    async fn get_state_proof(&self, keys: Vec<String>) -> RpcResult<StateProofResponse> {
        let parsed_keys = keys
            .iter()
            .map(|k| summit_types::ssz_tree_key::parse_key(k).map_err(RpcError::InvalidKey))
            .collect::<Result<Vec<_>, _>>()?;

        let (root, el_block_number, proofs) = self
            .finalizer_mailbox
            .generate_state_proof(parsed_keys)
            .await;

        Ok(StateProofResponse {
            root,
            el_block_number,
            proofs,
        })
    }
}
