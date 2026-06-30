use crate::account::{ValidatorAccount, ValidatorStatus};
use crate::execution_request::DepositRequest;
use crate::withdrawal::{PendingWithdrawal, WithdrawalKind};
use crate::{Digest, PublicKey};

use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::Address;
use commonware_codec::{DecodeExt, Write};
use commonware_cryptography::{Signer, bls12381, ed25519};

pub(crate) fn create_test_deposit_request(index: u64, amount: u64) -> DepositRequest {
    let mut withdrawal_credentials = [0u8; 32];
    withdrawal_credentials[0] = 0x01; // Eth1 withdrawal prefix
    for i in 0..20 {
        withdrawal_credentials[12 + i] = index as u8;
    }

    let consensus_key = bls12381::PrivateKey::from_seed(index);
    DepositRequest {
        node_pubkey: PublicKey::decode(&[1u8; 32][..]).unwrap(),
        consensus_pubkey: consensus_key.public_key(),
        withdrawal_credentials,
        amount,
        node_signature: [index as u8; 64],
        consensus_signature: [index as u8; 96],
        index,
    }
}

/// Build a deposit with valid node (ed25519) and consensus (BLS) signatures over
/// `as_message(domain)`, mirroring how a depositor signs off chain. The node
/// account key is `node_priv.public_key()`.
pub(crate) fn make_signed_deposit(
    node_priv: &ed25519::PrivateKey,
    bls_priv: &bls12381::PrivateKey,
    withdrawal_credentials: [u8; 32],
    amount: u64,
    index: u64,
    domain: Digest,
) -> DepositRequest {
    let mut deposit = DepositRequest {
        node_pubkey: node_priv.public_key(),
        consensus_pubkey: bls_priv.public_key(),
        withdrawal_credentials,
        amount,
        node_signature: [0u8; 64],
        consensus_signature: [0u8; 96],
        index,
    };
    let message = deposit.as_message(domain);

    let node_sig = node_priv.sign(&[], &message);
    deposit.node_signature.copy_from_slice(node_sig.as_ref());

    let bls_sig = bls_priv.sign(&[], &message);
    let mut bls_sig_buf: Vec<u8> = Vec::new();
    bls_sig.write(&mut bls_sig_buf);
    deposit.consensus_signature.copy_from_slice(&bls_sig_buf);

    deposit
}

/// Eth1 (0x01 prefixed) withdrawal credentials carrying a 20 byte address.
pub(crate) fn eth1_credentials(address_byte: u8) -> [u8; 32] {
    let mut credentials = [0u8; 32];
    credentials[0] = 0x01;
    for byte in credentials.iter_mut().skip(12) {
        *byte = address_byte;
    }
    credentials
}

pub(crate) fn create_test_withdrawal(index: u64, amount: u64, epoch: u64) -> PendingWithdrawal {
    PendingWithdrawal {
        inner: Withdrawal {
            index,
            validator_index: index * 10,
            address: Address::from([index as u8; 20]),
            amount,
        },
        pubkey: [index as u8; 32],
        balance_deduction: amount,
        epoch,
        kind: WithdrawalKind::Validator,
    }
}

pub(crate) fn create_test_validator_account(index: u64, balance: u64) -> ValidatorAccount {
    let consensus_key = bls12381::PrivateKey::from_seed(1);
    ValidatorAccount {
        consensus_public_key: consensus_key.public_key(),
        withdrawal_credentials: Address::from([index as u8; 20]),
        balance,
        status: ValidatorStatus::Active,
        has_pending_deposit: false,
        has_pending_withdrawal: false,
        joining_epoch: 0,
        last_deposit_index: index,
    }
}
