# Summit Architecture Overview

## System Design

Summit is a modular consensus client implementing the Simplex protocol for EVM-based blockchains. It follows an actor-based architecture with clear separation of concerns between consensus, execution, networking, and storage.

```
 ┌─────────────────────────────────────────────────────────────────────────────────┐                                  
 │                                  ORCHESTRATOR                                   │                                  
 │                                                                                 │                                  
 │  • Epoch transition management                                                  │                                  
 │  • Simplex engine lifecycle management                                          │                                  
 │  • Network channel multiplexing                                                 │                                  
 │  • Epoch boundary block synchronization                                         │                                  
 │                                                                                 │                                  
 │   orchestrator/src/actor.rs                                                     │                                  
 └────────────┬────────────────────────────────────────────────────────────────────┘                                  
              │                                                                                                       
              │ spawn/abort engines per epoch                                                                         
              │                                                                                                       
              ▼                                                                                                       
 ┌──────────────────────────┐                                                                                         
 │   SIMPLEX CONSENSUS      │                                                                                         
 │   (commonware_consensus) │                             ┌──────────────────────┐                                    
 │                          │                             │     FINALIZER        │                                    
 │  • Leader election       │                             │  (State Execution)   │                                    
 │  • View management       │                             │                      │                                    
 │  • Notarization (2/3+1)  │                             │  • Canonical state   │                                    
 │  • Finalization (3/3)    │                             │  • Fork states       │                                    
 │  • Reports consensus     │                             │  • Execute blocks    │                                    
 │    messages              │                             │  • Commit to engine  │                                    
 │                          │                             │  • Create checkpoints│                                    
 │  External crate          │                             │  • Store headers     │                                    
 └────────┬─────────────────┘                             │                      │                                    
          │                                               │  finalizer/src/      │                                    
          │ Automaton trait                               │  actor.rs            │                                    
          │ Relay trait                                   └──────────┬───────────┘                                    
          │                                                          │                                                
          ▼                                                          │                                                
 ┌──────────────────────────┐                                        │                                                
 │      APPLICATION         │                                        │                                                
 │   (Consensus Interface)  │                                        │                                                
 │                          │                                        │                                                
 │  • Propose(round, parent)│────────subscribe parent────────────────┤                                                
 │  • Verify(round, payload)│────────notify_at_height────────────────┤                                                
 │  • Broadcast(payload)    │────────get_aux_data────────────────────┤                                                
 │                          │                                        │                                                
 │  Implements:             │                                        │                                                
 │  - Automaton trait       │                                        │                                                
 │  - Relay trait           │                                        │                                                
 │                          │                                        │                                                
 │  application/src/actor.rs│                                        │                                                
 └────────┬─────────────────┘                                        │                                                
          │                                                          │                                                
          │ broadcast()                                              │                                                
          │ verified()                                               │                                                
          │ subscribe()                                              │                                                
          ▼                                                          │                                                
 ┌──────────────────────────┐                                        │                                                
 │        SYNCER            │                                        │                                                
 │  (Coordination Hub)      │                                        │                                                
 │                          │                                        │                                                
 │  • Block cache           │────────Update::NotarizedBlock──────────┤                                                
 │  • Finalization archive  │────────Update::FinalizedBlock──────────┤                                                
 │  • Finalized blocks      │────────Update::Tip─────────────────────┤                                                
 │  • Resolver (backfill)   │                                        │                                                
 │  • Broadcast engine      │                                        │                                                
 │  • Subscription mgmt     │                                        │                                                
 │                          │                                        │                                                
 │  Messages:               │                                        │                                                
 │  - Broadcast             │◄───────acknowledgement─────────────────┘                                                
 │  - Verified              │                                                                                         
 │  - Notarization          │◄───────Simplex reports via                                                              
 │  - Finalization          │        Reporter trait                                                                   
 │  - Subscribe             │                                                                                         
 │  - GetBlock              │                                                                                         
 │  - GetFinalization       │                                                                                         
 │                          │                                                                                         
 │  syncer/src/actor.rs     │                                                                                         
 └────────┬─────────────────┘                                                                                         
          │                                                                                                           
          │ buffered broadcast                                                                                        
          │ resolver requests                                                                                         
          ▼                                                                                                           
 ┌──────────────────────────┐                                                                                         
 │       NETWORK            │                                                                                         
 │                          │                                                                                         
 │  • Broadcast network     │                                                                                         
 │  • P2P resolver          │                                                                                         
 │  • Block propagation     │                                                                                         
 │                          │                                                                                         
 │  commonware_p2p          │                                                                                         
 │  commonware_broadcast    │                                                                                         
 └──────────────────────────┘                                                                                         
                                                                                                                      
                                                                                                                      
 ┌─────────────────────────────────────────────────────────────────────────────────┐                                  
 │                            EXTERNAL INTERFACES                                  │                                 
 └─────────────────────────────────────────────────────────────────────────────────┘                                  
                                                                                                                      
     APPLICATION & FINALIZER                                                                                          
             │                                                                                                        
             │ start_building_block(forkchoice, timestamp, withdrawals)                                               
             │ get_payload(payload_id)                                                                                
             │ commit_hash(forkchoice)                                                                                
             ▼                                                                                                        
     ┌──────────────────┐                                                                                             
     │  ENGINE CLIENT   │                                                                                             
     │                  │────────────────────────────────┐                                                            
     │  Interface to    │                                │                                                            
     │  Execution Layer │                                ▼                                                            
     │                  │                    ┌─────────────────────────┐                                              
     │  types/src/      │                    │  ETHEREUM EXECUTION     │                                              
     │  engine_client.rs│                    │  CLIENT (Reth, Geth)    │                                              
     └──────────────────┘                    │                         │                                              
                                             │  • Block building       │                                              
                                             │  • State execution      │                                              
                                             │  • Forkchoice updates   │                                              
                                             └─────────────────────────┘                                              
                                                                                                                      
     FINALIZER & SYNCER                                                                                               
             │                                                                                                        
             │ store_consensus_state()                                                                                
             │ get_consensus_state()                                                                                  
             │ store_finalized_checkpoint()                                                                           
             │ store_finalized_header()                                                                               
             ▼                                                                                                        
     ┌──────────────────┐                                                                                             
     │    STORAGE       │                                                                                             
     │                  │                                                                                             
     │  commonware_     │                                                                                             
     │  storage         │                                                                                             
     │                  │                                                                                             
     │  • ADB Store     │                                                                                             
     │    (append-only) │                                                                                             
     │  • Consensus     │                                                                                             
     │    state by      │                                                                                             
     │    height        │                                                                                             
     │  • Checkpoints   │                                                                                             
     │    by epoch      │                                                                                             
     │  • Finalized     │                                                                                             
     │    headers       │                                                                                             
     │    by height     │                                                                                             
     │                  │                                                                                             
     │  finalizer/src/  │                                                                                             
     │  db.rs           │                                                                                             
     └──────────────────┘  
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
- Maintain current validator set and staking information
- Process validator additions/removals based on execution layer events
- Manage consensus state transitions
- Handle withdrawal processing
- Create and verify checkpoints

### 3. Syncer (`syncer/`)

Manages block synchronization and network state

**Key Responsibilities:**
- Receive and cache blocks from network
- Resolve missing blocks through backfill
- Broadcast verified blocks to peers
- Maintain local block cache
- Coordinate synchronization with peers
- Push notarized and finalized blocks to the Finalizer Actor

### 4. Application (`application/`)

Manages consensus state and validator set

**Key Responsibilities:**
- Propose blocks when selected as leader
- Validate blocks received from network
- Coordinate with execution client via Engine API
- Maintain block cache for pending/finalized blocks

### 5. Orchestrator (`orchestrator/`)

Coordinates consensus activities

**Key Responsibilities:**
- Epoch transition management
- Simplex engine lifecycle management
- Network channel multiplexing
- Epoch boundary block synchronization

## Data Flow

### Block Production Flow

1. **Leader Selection**: Leader election is handled by the current Simplex instance
2. **Block Building**: Application requests block from execution client via Engine API
3. **Block Proposal**: Application broadcasts proposed block to network
4. **Block Validation**: Application of peer validators validate block
5. **Optimistic Execution**: Syncer sends notarized blocks to the finalizer for optimistic execution
6. **Finalization**: Syncer sends finalized blocks to the finalizer for finalization


### Block Reception Flow

1. **Block Reception**: Syncer receives block from network
2. **Block Caching**: Block stored in cache for validation
3. **Block Validation**: Execution client validates block via Engine API
5. **Optimistic Execution**: Finalizer optimistically executes notarized block
5. **Block Finalization**: Finalizer applies finalized block


### Synchronization Flow

1. **State Discovery**: Syncer discovers missing blocks/state
2. **Block Resolution**: Resolver fetches missing blocks from peers
3. **Validation**: Each block validated via execution client
4. **State Application**: Validated blocks applied to consensus state


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