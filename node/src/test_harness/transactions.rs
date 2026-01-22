use alloy::hex;
use alloy::network::TransactionBuilder;
use alloy::providers::{Provider, WalletProvider};
use alloy::rpc::types::TransactionRequest;
use alloy_primitives::{Address, U256, keccak256};
use summit_types::execution_request::compute_deposit_data_root;

/// Send a deposit transaction to the deposit contract.
///
/// # Arguments
/// * `provider` - The alloy provider with wallet for signing transactions
/// * `deposit_contract_address` - Address of the deposit contract
/// * `deposit_amount` - Amount to deposit in wei
/// * `node_pubkey` - 32-byte ED25519 public key of the validator
/// * `consensus_pubkey` - 48-byte BLS public key of the validator
/// * `withdrawal_credentials` - 32-byte withdrawal credentials
/// * `node_signature` - 64-byte ED25519 signature
/// * `consensus_signature` - 96-byte BLS signature
/// * `nonce` - Transaction nonce
#[allow(clippy::too_many_arguments)]
pub async fn send_deposit_transaction<P>(
    provider: &P,
    deposit_contract_address: Address,
    deposit_amount: U256,
    node_pubkey: &[u8; 32],
    consensus_pubkey: &[u8; 48],
    withdrawal_credentials: &[u8; 32],
    node_signature: &[u8; 64],
    consensus_signature: &[u8; 96],
    nonce: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    P: Provider + WalletProvider,
{
    // Compute the correct deposit data root for this transaction
    let deposit_data_root = compute_deposit_data_root(
        node_pubkey,
        consensus_pubkey,
        withdrawal_credentials,
        deposit_amount,
        node_signature,
        consensus_signature,
    );

    // Create deposit function call data: deposit(bytes,bytes,bytes,bytes,bytes,bytes32)
    let function_selector = &keccak256("deposit(bytes,bytes,bytes,bytes,bytes,bytes32)")[0..4];
    let mut call_data = function_selector.to_vec();

    // ABI encode parameters - calculate offsets for 6 parameters (5 dynamic + 1 fixed)
    let offset_to_node_pubkey = 6 * 32;
    let offset_to_consensus_pubkey =
        offset_to_node_pubkey + 32 + node_pubkey.len().div_ceil(32) * 32;
    let offset_to_withdrawal_creds =
        offset_to_consensus_pubkey + 32 + consensus_pubkey.len().div_ceil(32) * 32;
    let offset_to_node_signature =
        offset_to_withdrawal_creds + 32 + withdrawal_credentials.len().div_ceil(32) * 32;
    let offset_to_consensus_signature =
        offset_to_node_signature + 32 + node_signature.len().div_ceil(32) * 32;

    // Add parameter offsets
    let mut offset_bytes = vec![0u8; 32];
    offset_bytes[28..32].copy_from_slice(&(offset_to_node_pubkey as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_consensus_pubkey as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_withdrawal_creds as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_node_signature as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_consensus_signature as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    // Add the fixed bytes32 parameter (deposit_data_root)
    call_data.extend_from_slice(&deposit_data_root);

    // Add dynamic data
    let mut length_bytes = [0u8; 32];

    // Node pubkey (32 bytes ed25519)
    length_bytes[28..32].copy_from_slice(&(node_pubkey.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(node_pubkey);

    // Consensus pubkey (48 bytes BLS)
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(consensus_pubkey.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(consensus_pubkey);
    call_data.extend_from_slice(&[0u8; 16]); // Pad 48 to 64 bytes (next 32-byte boundary)

    // Withdrawal credentials (32 bytes)
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(withdrawal_credentials.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(withdrawal_credentials);

    // Node signature (64 bytes ed25519)
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(node_signature.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(node_signature);

    // Consensus signature (96 bytes BLS)
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(consensus_signature.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(consensus_signature);

    let tx_request = TransactionRequest::default()
        .with_to(deposit_contract_address)
        .with_value(deposit_amount)
        .with_input(call_data)
        .with_gas_limit(500_000)
        .with_gas_price(1_000_000_000) // 1 gwei
        .with_nonce(nonce);

    println!(
        "Sending deposit transaction to {} with amount {} wei (nonce: {})",
        deposit_contract_address, deposit_amount, nonce
    );
    println!("  Node pubkey: 0x{}", hex::encode(node_pubkey));
    println!("  Consensus pubkey: 0x{}", hex::encode(consensus_pubkey));

    match provider.send_transaction(tx_request).await {
        Ok(pending) => {
            println!("Deposit transaction sent: {}", pending.tx_hash());
            match pending.get_receipt().await {
                Ok(receipt) => {
                    println!("Deposit transaction receipt:");
                    println!("  Block number: {:?}", receipt.block_number);
                    println!("  Gas used: {:?}", receipt.gas_used);
                    println!("  Status: {:?}", receipt.status());
                    Ok(())
                }
                Err(e) => panic!("Transaction failed: {e}"),
            }
        }
        Err(e) => panic!("Error sending transaction: {}", e),
    }
}
