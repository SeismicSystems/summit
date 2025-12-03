# Summit Architecture Overview

## System Design

Summit is a modular consensus client implementing the Simplex protocol for EVM-based blockchains. It follows an actor-based architecture with clear separation of concerns between consensus, execution, networking, and storage.

```
┌─────────────────────────────────────────────────────────────┐
│                    Summit Consensus Client                  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │ RPC Server  │  │ Orchestrator │  │    Application      │ │
│  │ (External   │  │ (Consensus   │  │ (State Management)  │ │
│  │  API)       │  │ Coordination)│  │                     │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
│         │                │                      │           │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │   Syncer    │  │  Finalizer   │  │  Buffer/Broadcast   │ │
│  │ (Block Sync │  │ (Block Prod. │  │ (Network Buffering) │ │
│  │  & Valid'n) │  │  & Finality) │  │                     │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
│         │                │                      │           │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │  Storage    │  │ Engine Client│  │      P2P Network    │ │
│  │ (Consensus  │  │ (Execution   │  │  (Validator Comm.)  │ │
│  │  State)     │  │  Interface)  │  │                     │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                           │
                    ┌──────────────┐
                    │   Reth/Geth  │
                    │  (Execution  │
                    │   Client)    │
                    └──────────────┘
```

## Core Components

### 1. Engine (`node/src/engine.rs`)

The central coordinator that orchestrates all components

**Key Responsibilities:**
- Component lifecycle management
- Message routing between actors
- Configuration management
- Graceful shutdown coordination

### 2. Finalizer (`finalizer/`)

Handles block production, validation, and finalization with Reth

**Key Responsibilities:**
- Block proposal when selected as leader
- Block validation from other validators
- Consensus finalization via Simplex protocol
- Execution client coordination (Engine API)

### 3. Syncer (`syncer/`)

Manages block synchronization and network state

**Key Responsibilities:**
- Block reception and validation
- Missing block resolution
- Network state synchronization
- Block propagation to peers

### 4. Application (`application/`)

Manages consensus state and validator set

**Key Responsibilities:**
- Validator set management
- Consensus state transitions
- Checkpoint creation and verification
- Staking/unstaking logic

### 5. Orchestrator (`orchestrator/`)

Coordinates consensus activities

**Key Responsibilities:**
- Handles Simplex instances for each epoch
- Activity broadcast and reception
- Timeout management
- View change coordination

## Data Flow

### Block Production Flow

1. **Leader Selection**: Leader election is handled by the current Simplex instance
2. **Block Building**: Finalizer requests block from execution client via Engine API
3. **Block Proposal**: Finalizer broadcasts proposed block to network
4. **Block Validation**: Peer validators validate block via execution client
5. **Consensus**: Orchestrator coordinates consensus on proposed block
6. **Finalization**: Finalizer commits finalized block to execution client

```
Orchestrator → Finalizer → EngineClient → Reth → EngineClient → Finalizer → Network
```

### Block Reception Flow

1. **Block Reception**: Syncer receives block from network
2. **Block Caching**: Block stored in cache for validation
3. **Block Validation**: Execution client validates block via Engine API
4. **Consensus Participation**: Orchestrator participates in consensus
5. **Block Finalization**: Finalizer applies finalized block

```
Network → Syncer → Cache → EngineClient → Reth → EngineClient → Orchestrator → Finalizer
```

### Synchronization Flow

1. **State Discovery**: Syncer discovers missing blocks/state
2. **Block Resolution**: Resolver fetches missing blocks from peers
3. **Validation**: Each block validated via execution client
4. **State Application**: Validated blocks applied to consensus state

```
Syncer → Resolver → Peers → EngineClient → Reth → Application → ConsensusState
```

## Actor Communication

Summit uses message passing between actors with typed mailboxes

**Message Flow Patterns:**
- **Request-Response**: Synchronous queries (e.g., validator set queries)
- **Fire-and-Forget**: Asynchronous notifications (e.g., block notifications)
- **Broadcast**: Network-wide messages (e.g., consensus activities)

## Storage Architecture

Summit uses Commonware's storage primitives for persistent state

**Storage Patterns:**
- **Immutable Blocks**: Once finalized, blocks never change
- **Versioned State**: Consensus state with rollback capability
- **Compressed Archives**: Historical data compressed and archived
- **Atomic Updates**: State changes applied atomically

## Performance Characteristics

### Throughput Optimizations
- **Parallel Validation**: Multiple blocks validated concurrently
- **Pipelined Consensus**: Block production/validation overlapped
- **Efficient Caching**: In-memory caches for hot data
- **Batch Processing**: Multiple operations batched for efficiency

### Latency Optimizations
- **Simplex Protocol**: Responsive consensus with adaptive timeouts
- **Pre-computation**: Next block building started early
- **Efficient Serialization**: Optimized encoding/decoding
- **Direct IPC**: Low-latency communication with execution client

## Security Model

### Trust Boundaries
1. **Network Boundary**: All network communication authenticated
2. **Execution Boundary**: Engine API isolates consensus from execution
3. **Storage Boundary**: Cryptographic verification of all stored data
4. **Consensus Boundary**: BFT consensus tolerates f < n/3 Byzantine faults

### Threat Model
- **Network Attacks**: Authenticated P2P prevents impersonation
- **Consensus Attacks**: Simplex protocol handles Byzantine validators
- **Execution Attacks**: Engine API isolation prevents direct EVM access
- **Storage Attacks**: Cryptographic verification prevents tampering