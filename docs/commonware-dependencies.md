# Commonware Dependencies Analysis

Summit leverages the [Commonware library](https://commonware.xyz) extensively for consensus, cryptography, networking, and storage primitives. This document provides a comprehensive analysis of how Commonware components are integrated and used.

## Core Dependencies

### 1. Consensus (`commonware-consensus`)

**Used for**: Simplex consensus protocol implementation

**Key Components:**
- `simplex` - Simplex consensus engine
- `simplex::scheme::Scheme` - Signature verification scheme
- `types::{Epoch, Epocher, FixedEpocher, Round, View, ViewDelta, Height}` - Consensus primitives
- `Block` trait - Block interface definition
- `Reporter` trait - Hook for consensus activity notifications

**Critical Usage:**
- **Consensus Protocol**: All consensus logic delegated to Commonware's Simplex implementation
- **Byzantine Fault Tolerance**: Handles f < n/3 Byzantine validators
- **Liveness Guarantees**: Adaptive timeouts for network conditions
- **Safety Guarantees**: Cryptographic consensus finality

### 2. Cryptography (`commonware-cryptography`)

**Used for**: All cryptographic operations including signatures and hashing

**Key Components:**
- `bls12381` - BLS signature scheme for consensus
- `ed25519` - EdDSA signatures for networking
- `sha256` - Cryptographic hashing
- `Signer` trait - Generic signing interface

**Critical Usage:**
- **Consensus Signatures**: BLS12-381 MinPk variant for consensus activities and multisig schemes
- **Network Authentication**: Ed25519 for P2P communication and validator identity
- **Block Hashing**: SHA256 for content addressing
- **Key Management**: Secure key generation and storage

### 3. Networking (`commonware-p2p`)

**Used for**: Peer-to-peer communication between validators

**Key Components:**
- `authenticated` - Authenticated P2P connections (production)
- `simulated` - In-process network (deterministic tests)
- `Manager`, `Provider`, `TrackedPeers`, `PeerSetSubscription` - Peer set management
- `Sender`/`Receiver` - Message transmission
- `Blocker`, `Ingress` - Connection filtering and admission

**Critical Usage:**
- **Validator Discovery**: Automatic peer discovery and connection
- **Message Authentication**: Cryptographically authenticated channels
- **Consensus Communication**: Reliable delivery of consensus messages
- **Block Propagation**: Efficient block and activity broadcast

### 4. Storage (`commonware-storage`)

**Used for**: Persistent storage of consensus state and blocks

**Key Components:**
- `qmdb::store::db::Db` - QMDB authenticated key-value store (consensus state, headers)
- `archive` / `archive::immutable` - Block archive keyed by height
- `journal::contiguous::variable` - Append-only write-ahead log
- `translator::EightCap` - Key translator for the QMDB store
- `metadata::Metadata` - Metadata store for pointer/tip data

**Critical Usage:**
- **State Persistence**: Consensus state, validator set, and finalized headers in QMDB
- **Block Storage**: Finalized blocks archived by height via `archive::immutable`
- **Atomic Updates**: Journal-backed writes with WAL semantics
- **Checkpoints**: Durable checkpoint records for fast sync

### 5. Runtime (`commonware-runtime`)

**Used for**: Async runtime abstractions and utilities

**Key Components:**
- `tokio::Runner` - Production async runtime (wraps Tokio)
- `deterministic::Runner` - Seeded, deterministic runtime for tests
- `Clock`, `Spawner`, `Handle` - Time, task spawning, and join handles
- `Metrics` - Prometheus-compatible metrics registry
- `Network`, `Storage` - Abstract network and disk interfaces
- `buffer::paged::CacheRef`, `BufferPooler` - Paged buffer caching for storage

**Critical Usage:**
- **Task Management**: Async task spawning and coordination
- **Time Management**: Consensus timeouts and timing
- **Resource Management**: Memory pools and buffer management
- **Testing Support**: Deterministic runtime for testing

### 6. Utilities (`commonware-utils`)

**Used for**: Common data structures and utilities

**Key Components:**
- `NZU64`, `NZUsize` - Non-zero integer types (and their constructor macros)
- `channel::{mpsc, oneshot}` - Inter-actor channels
- `vec::NonEmptyVec`, `ordered` - Non-empty vectors and ordered sets/maps
- `Hostname` - Validated hostname type for bootstrap configuration
- `acknowledgement::{Acknowledgement, Exact}` - Activity acknowledgement tracking

Hex encoding/decoding moved to `commonware-formatting` in 2026.5.0.

### 7. Codec (`commonware-codec`)

**Used for**: Efficient serialization and deserialization

**Key Components:**
- `Codec` trait - Generic encoding interface
- `Encode`/`Decode` - Serialization traits
- `ReadExt`/`WriteExt` - Stream utilities
- `varint` - Variable-length integer encoding

### 8. Broadcasting (`commonware-broadcast`)

**Used for**: Reliable message broadcasting to validator set

**Key Components:**
- `buffered::Engine` - Buffered broadcast engine
- `Broadcaster` - Message broadcasting interface
- Reliable delivery - Ensuring message delivery to all validators

### 9. Resolution (`commonware-resolver`)

**Used for**: Missing data resolution and backfill

**Key Components:**
- `Resolver` / `TargetedResolver` - Fetch interfaces (broadcast and peer-targeted)
- `Fetch` / `Delivery` - A fetch pairs a peer-visible `Key` with a local `Subscriber` annotation; deliveries return both so the consumer knows why the data was requested
- `Consumer`/`Producer` - Data request/response; `Consumer::deliver` returns a `oneshot::Receiver<bool>` so response validity is judged off the resolver loop
- `retain(predicate)` - Prunes outstanding fetches (e.g. below the syncer's processed floor)
- `p2p::Engine` - P2P resolution engine

### 10. Macros (`commonware-macros`)

**Used for**: Async control-flow macros and instrumented test harness

**Key Components:**
- `select!` / `select_loop!` - Async branching and loops (used in `application/`, `syncer/`)
- `test_traced!` - Instrumented test harness with deterministic tracing

### 11. Math (`commonware-math`)

**Used for**: Cryptographic randomness

**Key Components:**
- `algebra::Random` - Random key generation for BLS12-381 and Ed25519 schemes

**Critical Usage:**
- **Key Generation**: Deterministic randomness for consensus and node key creation in `node/src/keys.rs`
- **Testing**: Seeded randomness for reproducible test fixtures

### 12. Parallel (`commonware-parallel`)

**Used for**: Sequential and parallel processing strategies

**Key Components:**
- `Strategy` - Abstraction over execution strategies
- `Sequential` - Single-threaded execution strategy (used by the syncer and engine)

### 13. Actor (`commonware-actor`)

**Used for**: Actor mailboxes with explicit backpressure policies

**Key Components:**
- `mailbox::{new, Sender, Receiver}` - Bounded actor mailboxes with synchronous `enqueue`
- `mailbox::{Policy, Overflow}` - Per-message overflow handling when a mailbox fills (e.g. the syncer coalesces finalization hints per height instead of blocking callers)
- `Feedback` - Result of a synchronous send (`Ok`/`Backoff`/`Closed`), returned by `Reporter::report`, `Relay::broadcast`, and p2p oracle calls

**Critical Usage:**
- **Non-blocking control loops**: The orchestrator and application enqueue into the syncer mailbox without awaiting, so a slow syncer cannot park epoch transitions or consensus message handling

### 14. Formatting (`commonware-formatting`)

**Used for**: Hexadecimal encoding and decoding

**Key Components:**
- `hex` / `from_hex` - Hex encoding/decoding for keys, digests, and genesis configuration (moved out of `commonware-utils` in 2026.5.0)

## Security Analysis

### Cryptographic Security

**BLS12-381 Usage:**
- **Purpose**: Consensus signatures and multisig schemes for Simplex protocol
- **Implementation**: Commonware's audited BLS12-381 MinPk variant implementation
- **Security Level**: 128-bit security level
- **Current Status**: Active use in consensus layer via `bls12381_multisig::Scheme`

**Ed25519 Usage:**
- **Purpose**: Network authentication and validator identification
- **Implementation**: Commonware's Ed25519 implementation
- **Security Level**: 128-bit security level
- **Verification**: All network messages cryptographically authenticated

### Consensus Security

**Simplex Protocol:**
- **Byzantine Tolerance**: Tolerates f < n/3 Byzantine validators
- **Liveness**: Guaranteed progress under synchrony assumptions
- **Safety**: Cryptographic finality guarantees
- **Implementation**: Directly uses Commonware's Simplex implementation

**Message Authentication:**
- All consensus messages signed with validator keys
- Replay protection via sequence numbers
- Timeout management for liveness

### Network Security

**P2P Authentication:**
- All connections authenticated with Ed25519
- Peer identity verification before message processing
- Protection against Sybil attacks

**Message Integrity:**
- All messages are hashed & signed

## Performance Characteristics

### Optimizations from Commonware

**Zero-Copy Operations:**
- Efficient serialization with minimal copying
- Stream-based processing for large messages
- Memory pool management for reduced allocations

**Parallel Processing:**
- Concurrent signature verification
- Parallel block validation
- Asynchronous I/O throughout

**Caching and Buffering:**
- Intelligent caching of frequently accessed data
- Buffer pools for network operations
- Compression for historical data

### Benchmarking Support

Commonware provides deterministic runtime for reproducible benchmarks:

```rust
#[cfg(test)]
use commonware_runtime::deterministic::Runner;
use commonware_macros::test_traced;
```

## Trust Model

### What Summit Trusts in Commonware

1. **Consensus Correctness**: Simplex protocol implementation
2. **Cryptographic Security**: Signature schemes and hashing
3. **Network Security**: P2P authentication and message integrity
4. **Storage Integrity**: Atomic operations and data consistency

### What Summit Implements Independently

1. **Engine API Integration**: Communication with execution clients
2. **Application Logic**: Validator set management and staking
3. **Configuration Management**: Node configuration and deployment
4. **RPC Interface**: External API for clients

### Upgrade Path

Summit pins Commonware to a versioned release in the workspace `Cargo.toml`. All 14 `commonware-*` workspace dependencies are bumped in lockstep:

```toml
commonware-consensus = "2026.7.0"
commonware-cryptography = "2026.7.0"
# ...
```

To upgrade, bump the version across every `commonware-*` entry in the root `Cargo.toml` and run `cargo update -p commonware-consensus` (etc.).

### Syncer Durability

Summit's syncer is a fork of Commonware marshal with additional application reporting and checkpoint behavior. It preserves marshal's durability model while reporting notarized blocks to the finalizer for speculative execution:

- Proposed blocks are handed to the network before persistence starts so storage does not delay propagation.
- Proposed, verified, and certified writes return durability handles to the mailbox caller, which awaits them without blocking the syncer actor.
- Certified durability covers both the block and any accepted notarization for the round.
- Summit's `CertifiableAutomaton::certify` waits for the certified durability barrier before returning `true`, so Simplex cannot cast a finalize vote before the block is recoverable locally.
- Finalized blocks are not dispatched to the application until the finalized block and certificate archives are durable.
- Direct consensus notarizations start storage asynchronously and are reported through `Update::NotarizedBlock` only after both the block and notarization are durable; storage failures remain fatal.
- Resolver-delivered notarized data is made durable before repair and finalization bookkeeping advances.

## Audit Recommendations

When auditing Summit's Commonware usage:

1. **Verify Version**: Ensure the pinned Commonware release corresponds to an audited version
2. **Integration Points**: Review how Summit integrates Commonware APIs
3. **Configuration**: Verify Commonware components configured securely
4. **Error Handling**: Ensure proper error handling around Commonware calls
