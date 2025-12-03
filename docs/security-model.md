# Security Model

This document outlines Summit's security architecture, threat model, cryptographic primitives, and security boundaries. It provides auditors with a comprehensive understanding of how Summit maintains security across all system components.

## Security Architecture

### Trust Boundaries

Summit establishes several critical trust boundaries:

```
┌─────────────────────────────────────────────────────────────┐
│                    External Network                          │  ← Untrusted
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │   P2P Net   │  │   RPC API    │  │    Engine API       │ │  ← Authenticated
│  │ (Auth'd)    │  │  (Public)    │  │   (JWT Auth)        │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                  Summit Consensus Core                       │  ← Trusted
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │ Finalizer   │  │ Orchestrator │  │     Application     │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Execution Client                          │  ← Isolated
│                      (Reth/Geth)                            │
└─────────────────────────────────────────────────────────────┘
```

## Cryptographic Primitives

### Digital Signatures

Summit uses two signature schemes for different purposes:

#### Ed25519 (P2P Networking)
```rust
pub type PublicKey = commonware_cryptography::ed25519::PublicKey;
pub type PrivateKey = commonware_cryptography::ed25519::PrivateKey;
pub type Signature = commonware_cryptography::ed25519::Signature;
```

**Usage:**
- **Validator Identity**: Unique validator identification
- **Network Authentication**: P2P connection authentication
- **Consensus Activities**: Signing consensus messages and blocks
- **Security Level**: 128-bit security equivalent

**Properties:**
- **Deterministic**: Same message always produces same signature
- **Fast Verification**: Efficient batch verification for multiple signatures
- **Small Signatures**: 64-byte signatures for efficient network transmission

#### BLS12-381 (Consensus messages with aggregate signatures)
```rust
pub use commonware_cryptography::bls12381;
pub type MultisigScheme<C, V> = signing_scheme::bls12381_multisig::Scheme<C::PublicKey, V>;
```

**Current Usage:**
- **Consensus Signatures**: BLS12-381 MinPk variant for Simplex consensus activities
- **Multisig Schemes**: Aggregate signatures for validator consensus participation
- **Signature Verification**: Efficient batch verification of consensus activities

### Cryptographic Hashing

```rust
pub type Digest = commonware_cryptography::sha256::Digest;
```

**SHA-256 Usage:**
- **Block Hashing**: Content addressing for all blocks
- **Merkle Trees**: State and transaction root calculations
- **Commitment Schemes**: Binding commitments for consensus
- **Key Derivation**: Deriving keys from master secrets

### Key Management

#### Validator Keys (`types/src/keystore.rs`)

```rust
pub struct KeyStore {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl KeyStore {
    pub fn new() -> Self {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        Self { private_key, public_key }
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        // Load encrypted key from disk with password protection
    }

    pub fn save_to_file(&self, path: &Path, password: &str) -> Result<()> {
        // Save encrypted key to disk with password protection
    }
}
```

**Key Security Properties:**
- Saved to disk but in the secure enclave only accessible from within 
- **Secure Generation**: Cryptographically secure random number generation
- **Memory Safety**: Keys zeroized after use to prevent memory attacks

## Network Security

### P2P Authentication

All peer-to-peer communication is cryptographically authenticated:

```rust
// orchestrator/src/actor.rs
use commonware_p2p::authenticated::{Handshake, Receiver, Sender};

// Authentication handshake with cryptographic verification
async fn authenticate_peer(
    peer_public_key: &PublicKey,
    connection: &mut Connection
) -> Result<()> {
    // Perform cryptographic handshake
    let handshake = Handshake::new(our_private_key);
    let authenticated_channel = handshake.complete(connection, peer_public_key).await?;
    Ok(())
}
```

**Authentication Properties:**
- **Mutual Authentication**: Both peers verify each other's identity
- **Perfect Forward Secrecy**: Session keys derived independently
- **Replay Protection**: Nonces prevent message replay attacks
- **Identity Verification**: Peer public keys verified against validator set

### Message Integrity

All network messages include cryptographic integrity protection:

```rust
// Message signing for network transmission
pub struct AuthenticatedMessage<T> {
    payload: T,
    signature: Signature,
    sender: PublicKey,
    nonce: u64,
}

impl<T: Encode> AuthenticatedMessage<T> {
    pub fn new(payload: T, signer: &impl Signer) -> Self {
        let mut message_bytes = Vec::new();
        payload.encode(&mut message_bytes);
        let signature = signer.sign(&message_bytes);
        
        Self {
            payload,
            signature,
            sender: signer.public_key(),
            nonce: generate_nonce(),
        }
    }

    pub fn verify(&self) -> bool {
        let mut message_bytes = Vec::new();
        self.payload.encode(&mut message_bytes);
        self.signature.verify(&message_bytes, &self.sender)
    }
}
```

## Consensus Security

### Byzantine Fault Tolerance

Summit implements the Simplex consensus protocol through Commonware:

```rust
// Consensus safety properties
pub struct ConsensusState<V> {
    current_view: u64,
    current_epoch: u64,
    validator_set: ValidatorSet<PublicKey>,
    finalized_blocks: Vec<Block<Signature, V>>,
}
```

**BFT Properties:**
- **Safety**: No two conflicting blocks can be finalized
- **Liveness**: Progress guaranteed with ≥ 2f+1 honest validators  
- **Byzantine Tolerance**: Tolerates up to f < n/3 Byzantine validators
- **Finality**: Cryptographic finality with no rollbacks

### Activity Verification

All consensus activities are cryptographically verified:

```rust
// Activity verification in orchestrator
impl<E, O, V, S, A> Actor<E, O, V, S, A> {
    async fn verify_activity(
        &self,
        activity: &Activity,
        validator_set: &ValidatorSet<PublicKey>
    ) -> bool {
        // 1. Verify signature
        if !activity.signature.verify(&activity.encode(), &activity.signer) {
            return false;
        }
        
        // 2. Verify signer is valid validator
        if !validator_set.contains(&activity.signer) {
            return false;
        }
        
        // 3. Verify activity is for current view
        if activity.view != self.current_view {
            return false;
        }
        
        true
    }
}
```

## Execution Security

### Engine API Isolation

Summit communicates with execution clients exclusively through the Engine API:

```rust
// No direct access to execution state
pub trait EngineClient: Clone + Send + Sync + 'static {
    // Only these specific methods allowed
    fn start_building_block(...) -> impl Future<Output = Option<PayloadId>>;
    fn get_payload(...) -> impl Future<Output = ExecutionPayloadEnvelopeV4>;
    fn check_payload(...) -> impl Future<Output = PayloadStatus>;
    fn commit_hash(...) -> impl Future<Output = ()>;
}
```

**Isolation Properties:**
- **Interface Restriction**: Only predefined Engine API methods accessible
- **State Encapsulation**: No direct access to execution state
- **Validation Isolation**: Execution client validates all state transitions
- **Error Isolation**: Execution errors don't affect consensus state

### JWT Authentication

Engine API access protected by JWT tokens:

```rust
// JWT authentication for Engine API
use alloy_transport_http::jwt_auth::JwtAuth;

impl RethEngineClient {
    pub async fn new(engine_ipc_path: String, jwt_secret: &[u8]) -> Self {
        let auth = JwtAuth::new(jwt_secret);
        let provider = ProviderBuilder::default()
            .connect_ipc_with_auth(ipc, auth)
            .await
            .unwrap();
        Self { provider }
    }
}
```

## Threat Model

### Covered Threats

#### 1. Network Attacks

**Threat**: Malicious peers attempting to disrupt consensus
**Mitigation**: 
- Cryptographic authentication of all peers
- Signature verification on all messages
- Validator set membership verification

**Threat**: Man-in-the-middle attacks
**Mitigation**:
- Perfect forward secrecy in P2P connections
- End-to-end message authentication
- Public key verification against validator set

#### 2. Consensus Attacks

**Threat**: Byzantine validators attempting to fork the chain
**Mitigation**:
- BFT consensus tolerating f < n/3 Byzantine validators
- Cryptographic finality preventing rollbacks
- Activity verification before processing

**Threat**: Double-spending or conflicting blocks
**Mitigation**:
- Consensus protocol guarantees single canonical chain
- Cryptographic block verification
- Finality prevents transaction reversals

#### 3. Execution Attacks

**Threat**: Malicious execution client behavior
**Mitigation**:
- Engine API isolation limits attack surface
- IPC from within enclave to restrict access
- Payload verification before consensus

**Threat**: State corruption or manipulation
**Mitigation**:
- Execution client validates all state transitions
- Cryptographic verification of execution payloads
- Consensus layer doesn't directly access execution state

#### 4. Storage Attacks

**Threat**: Data corruption or manipulation
**Mitigation**:
- Cryptographic integrity verification
- Immutable storage for finalized data
- Atomic updates with rollback capability

### Not Covered (Out of Scope)

#### 1. Execution Layer Vulnerabilities
- EVM bugs or vulnerabilities in smart contracts
- Execution client implementation bugs
- State transition function correctness

#### 2. Operating System Security
- Host OS security and updates
- Container security (if applicable)
- Hardware security and trust

#### 3. Social Engineering
- Validator key compromise through social means
- Phishing attacks against operators
- Supply chain attacks on dependencies

#### 4. Physical Security
- Physical access to validator hardware
- Hardware tampering or side-channel attacks
- Power analysis or electromagnetic attacks

## Security Best Practices

### Network Security

1. **Firewall Configuration**: Restrict network access to essential ports only
2. **TLS Encryption**: Use TLS for all non-P2P network communication
3. **Access Control**: Limit RPC access to trusted clients
4. **Monitoring**: Log and monitor all network connections

### Operational Security

1. **Regular Updates**: Keep Summit and dependencies updated
2. **Security Monitoring**: Monitor for security advisories
3. **Incident Response**: Prepare incident response procedures
4. **Backup Strategy**: Regular backups with secure storage

### Development Security

1. **Code Review**: All code changes reviewed for security implications
2. **Static Analysis**: Use static analysis tools to detect vulnerabilities
3. **Dependency Management**: Regular audit of dependencies
4. **Testing**: Comprehensive security testing including fuzzing

## Audit Recommendations

### Focus Areas for Security Audits

1. **Cryptographic Implementation**
   - Verify correct usage of Commonware cryptographic primitives
   - Validate signature verification logic

2. **Consensus Protocol**
   - Review Simplex protocol integration
   - Verify Byzantine fault tolerance properties
   - Validate activity verification and processing

3. **Network Security**
   - Audit P2P authentication mechanisms
   - Review message integrity and replay protection
   - Validate peer verification logic

4. **Engine API Integration**
   - Review JWT authentication implementation
   - Validate input sanitization and error handling
   - Audit payload verification logic

5. **Storage Security**
   - Review data integrity mechanisms
   - Validate atomic update procedures
   - Audit backup and recovery processes

### Security Testing

1. **Penetration Testing**: Test network and RPC interfaces
2. **Fuzzing**: Fuzz network message parsing and consensus logic
3. **Cryptographic Testing**: Verify cryptographic implementations
4. **Byzantine Testing**: Test behavior under Byzantine conditions

The security model is designed to provide defense in depth with multiple layers of protection and clear trust boundaries between components.