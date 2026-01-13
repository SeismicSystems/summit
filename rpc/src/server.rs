use crate::api::SummitApiServer;
use crate::error::RpcError;
use crate::types::{
    CheckpointInfoRes, CheckpointRes, DepositTransactionResponse, PublicKeysResponse,
};
use alloy_primitives::{Address, U256, hex::FromHex as _};
use async_trait::async_trait;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{Hasher as _, Sha256, Signer};
use commonware_utils::from_hex_formatted;
use jsonrpsee::core::RpcResult;
use ssz::Encode as _;
use summit_finalizer::FinalizerMailbox;
use summit_types::Block;
use summit_types::scheme::MultisigScheme;
use summit_types::{
    KeyPaths, PROTOCOL_VERSION, PublicKey,
    execution_request::{DepositRequest, compute_deposit_data_root},
};

pub struct SummitRpcServer {
    key_store_path: String,
    finalizer_mailbox: FinalizerMailbox<MultisigScheme, Block>,
}

impl SummitRpcServer {
    pub fn new(
        key_store_path: String,
        finalizer_mailbox: FinalizerMailbox<MultisigScheme, Block>,
    ) -> Self {
        Self {
            key_store_path,
            finalizer_mailbox,
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

        let Some(checkpoint) = maybe_checkpoint else {
            return Err(RpcError::CheckpointNotFound.into());
        };

        Ok(CheckpointRes {
            checkpoint: checkpoint.as_ssz_bytes(),
            digest: checkpoint.digest.0,
            epoch,
        })
    }

    async fn get_latest_checkpoint(&self) -> RpcResult<CheckpointRes> {
        let maybe_checkpoint = self.finalizer_mailbox.clone().get_latest_checkpoint().await;

        let (Some(checkpoint), epoch) = maybe_checkpoint else {
            return Err(RpcError::CheckpointNotFound.into());
        };

        Ok(CheckpointRes {
            checkpoint: checkpoint.as_ssz_bytes(),
            digest: checkpoint.digest.0,
            epoch,
        })
    }

    async fn get_latest_checkpoint_info(&self) -> RpcResult<CheckpointInfoRes> {
        let maybe_checkpoint = self.finalizer_mailbox.clone().get_latest_checkpoint().await;

        let (Some(checkpoint), epoch) = maybe_checkpoint else {
            return Err(RpcError::CheckpointNotFound.into());
        };

        Ok(CheckpointInfoRes {
            epoch,
            digest: checkpoint.digest.0,
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
}
