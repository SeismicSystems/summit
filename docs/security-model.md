# Security Model

This document outlines Summit's security architecture, threat model, cryptographic primitives, and security boundaries. It provides a comprehensive understanding of how Summit maintains security across all system components.

## Security Architecture

### Trust Boundaries

Summit establishes several critical trust boundaries:

```
┌─────────────────────────────────────────────────────────────┐
│                    External Network                         │  ← Untrusted
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │   P2P Net   │  │   RPC API    │  │     Engine API      │ │  ← Authenticated
│  │  (Auth'd)   │  │   (Public)   │  │     (JWT Auth)      │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                  Summit Consensus Core                      │  ← Trusted
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │  Finalizer  │  │ Orchestrator │  │     Application     │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Execution Client                         │  ← Isolated
│                      (Reth/Geth)                            │
└─────────────────────────────────────────────────────────────┘
```

## Cryptographic Primitives

### Digital Signatures

Summit uses two signature schemes for different purposes:

- **BLS12-381**, to sign blocks with aggregate signatures
- **Ed25519**, to sign all other P2P messages
  - These messages may include blocks signed with BLS12-381

### Cryptographic Hashing

We use SHA-256 in several places:
- **Block Hashing**: Content addressing for all blocks
- **Merkle Trees**: State and transaction root calculations
- **Commitment Schemes**: Binding commitments for consensus
- **Key Derivation**: Deriving keys from master secrets

## Network Security

### P2P Authentication

All peer-to-peer communication is cryptographically authenticated with the following properties:
- **Mutual Authentication**: Both peers verify each other's identity
- **Perfect Forward Secrecy**: Session keys derived independently
- **Replay Protection**: Nonces prevent message replay attacks
- **Identity Verification**: Peer public keys verified against validator set

## BFT Properties
- **Safety**: No two conflicting blocks can be finalized
- **Liveness**: Progress guaranteed with ≥ 2f+1 honest validators  
- **Byzantine Tolerance**: Tolerates up to f < n/3 Byzantine validators
- **Finality**: Cryptographic finality with no rollbacks

## Execution Security

### Engine API Isolation

Summit communicates with execution clients exclusively through the Engine API:

```rust
// NOTE: no direct access to execution state
pub trait EngineClient: Clone + Send + Sync + 'static {
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
