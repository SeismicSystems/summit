# Actor System Architecture

Summit implements an actor-based architecture where independent components communicate through typed message passing. This document details the actor system design, message flows, and coordination patterns.

## Actor Model Overview

Summit's architecture follows the actor model with these key principles:

- **Isolation**: Each actor maintains its own state and memory
- **Message Passing**: Actors communicate exclusively through messages
- **Asynchronous**: All actor interactions are non-blocking
- **Type Safety**: Message types are statically verified
- **Supervision**: Actors can supervise and restart child actors

```
┌─────────────────────────────────────────────────────────────┐
│                        Engine                               │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │ Application │  │ Orchestrator │  │     Finalizer       │ │
│  │   Actor     │  │    Actor     │  │      Actor          │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
│         │                │                      │           │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │   Syncer    │  │  Buffer/     │  │    RPC Server       │ │
│  │   Actor     │  │ Broadcast    │  │                     │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Core Actors

### 1. Application Actor (`application/src/actor.rs`)

**Purpose**: Manages consensus state, validator set, and staking logic

```rust
pub struct Actor<E, C, S, PK, SGN, V> {
    context: E,
    consensus_state: ConsensusState<V>,
    validators: ValidatorSet<PK>,
    engine_client: C,
    signer: S,
    mailbox: Mailbox<ApplicationMessage<PK>>,
}

pub enum ApplicationMessage<PK> {
    ProcessBlock(Block<SGN, V>),
    GetValidators(oneshot::Sender<Vec<PK>>),
    UpdateValidatorSet(ValidatorUpdate<PK>),
    GetConsensusState(oneshot::Sender<ConsensusState<V>>),
    ProcessWithdrawals(Vec<PendingWithdrawal>),
    ProcessCheckpoint(Checkpoint<V>),
}
```

**Key Responsibilities:**
- Maintain current validator set and staking information
- Process validator additions/removals based on execution layer events
- Manage consensus state transitions
- Handle withdrawal processing
- Create and verify checkpoints

**Message Handling Pattern:**
```rust
impl<E, C, S, PK, SGN, V> Actor<E, C, S, PK, SGN, V> {
    pub async fn run(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                Some(msg) = self.mailbox.recv() => {
                    match msg {
                        ApplicationMessage::ProcessBlock(block) => {
                            self.process_block(block).await?;
                        },
                        ApplicationMessage::GetValidators(tx) => {
                            let validators = self.validators.active_set();
                            tx.send(validators).ok();
                        },
                        // Handle other message types...
                    }
                },
                _ = self.context.cancelled() => break,
            }
        }
        Ok(())
    }
}
```

### 2. Finalizer Actor (`finalizer/src/actor.rs`)

**Purpose**: Handles block production, validation, and finalization

```rust
pub struct Finalizer<E, C, O, S, V> {
    context: E,
    engine_client: C,
    oracle: O,
    signer: S,
    consensus_state: ConsensusState<V>,
    pending_blocks: HashMap<Digest, Block<S, V>>,
    finalized_blocks: Vec<Block<S, V>>,
    mailbox: FinalizerMailbox<S, Block<S, V>>,
}

pub enum FinalizerMessage<S, B> {
    ProposeBlock(ProposeBlockRequest),
    ValidateBlock(B),
    FinalizeBlock(B),
    GetPendingBlocks(oneshot::Sender<Vec<B>>),
    ProcessFinalization(Finalization<S>),
}
```

**Key Responsibilities:**
- Propose blocks when selected as leader
- Validate blocks received from network
- Coordinate with execution client via Engine API
- Process consensus finalization messages
- Maintain block cache for pending/finalized blocks

**Block Production Flow:**
```rust
impl<E, C, O, S, V> Finalizer<E, C, O, S, V> {
    async fn handle_propose_block(&mut self, request: ProposeBlockRequest) -> Result<()> {
        // 1. Request block building from execution client
        let payload_id = self.engine_client
            .start_building_block(request.forkchoice_state, request.timestamp, request.withdrawals)
            .await?;
            
        // 2. Wait for block to be built
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // 3. Retrieve built block
        let envelope = self.engine_client.get_payload(payload_id).await?;
        
        // 4. Create consensus block
        let block = Block::new(
            envelope.execution_payload,
            request.aux_data,
            &self.signer
        );
        
        // 5. Broadcast to network
        self.broadcast_block(block).await?;
        
        Ok(())
    }
}
```

### 3. Syncer Actor (`syncer/src/actor.rs`)

**Purpose**: Manages block synchronization, caching, and network state

```rust
pub struct Actor<E, B, P, S> {
    context: E,
    cache: Cache<B>,
    resolver: Resolver<P>,
    broadcast: Broadcaster<B>,
    mailbox: SyncerMailbox<S, B>,
}

pub enum SyncerMessage<S, B> {
    ReceiveBlock(B),
    RequestBlocks(BlockRange),
    CacheBlock(B),
    GetCachedBlock(Digest, oneshot::Sender<Option<B>>),
    SyncToHeight(u64),
}
```

**Key Responsibilities:**
- Receive and cache blocks from network
- Resolve missing blocks through backfill
- Broadcast verified blocks to peers
- Maintain local block cache
- Coordinate synchronization with peers

**Block Reception Flow:**
```rust
impl<E, B, P, S> Actor<E, B, P, S> {
    async fn handle_receive_block(&mut self, block: B) -> Result<()> {
        // 1. Validate block structure
        if !self.validate_block_structure(&block) {
            return Err("Invalid block structure");
        }
        
        // 2. Cache block for processing
        self.cache.insert(block.hash(), block.clone()).await?;
        
        // 3. Check for missing dependencies
        if !self.cache.contains(&block.parent_hash()) {
            self.request_missing_blocks(block.parent_hash()).await?;
        }
        
        // 4. Forward to finalizer for validation
        self.finalizer_mailbox.send(FinalizerMessage::ValidateBlock(block)).await?;
        
        Ok(())
    }
}
```

### 4. Orchestrator Actor (`orchestrator/src/actor.rs`)

**Purpose**: Coordinates consensus protocol execution and activity management

```rust
pub struct Actor<E, O, V, S, A> {
    context: E,
    oracle: O,
    signer: S,
    application_mailbox: A,
    consensus: SimplexConsensus<V, S>,
    current_view: u64,
    activities: Vec<Activity>,
    mailbox: OrchestratorMailbox<S, Activity>,
}

pub enum OrchestratorMessage<S, A> {
    ReceiveActivity(A),
    StartNewRound(Round),
    ProcessTimeout(Timeout),
    GetCurrentView(oneshot::Sender<u64>),
    BroadcastActivity(A),
}
```

**Key Responsibilities:**
- Execute Simplex consensus protocol
- Coordinate consensus rounds and view changes
- Broadcast and receive consensus activities
- Manage consensus timeouts
- Interface with Commonware consensus primitives

**Consensus Activity Flow:**
```rust
impl<E, O, V, S, A> Actor<E, O, V, S, A> {
    async fn handle_receive_activity(&mut self, activity: Activity) -> Result<()> {
        // 1. Verify activity authenticity
        if !self.verify_activity_signature(&activity) {
            return Err("Invalid activity signature");
        }
        
        // 2. Check validator membership
        if !self.is_valid_validator(&activity.signer) {
            return Err("Activity from non-validator");
        }
        
        // 3. Process through consensus protocol
        let consensus_result = self.consensus.process_activity(activity).await?;
        
        // 4. Handle consensus decision
        match consensus_result {
            ConsensusDecision::Propose(block_request) => {
                self.finalizer_mailbox
                    .send(FinalizerMessage::ProposeBlock(block_request))
                    .await?;
            },
            ConsensusDecision::Finalize(block) => {
                self.finalizer_mailbox
                    .send(FinalizerMessage::FinalizeBlock(block))
                    .await?;
            },
            // Handle other decisions...
        }
        
        Ok(())
    }
}
```

## Message Passing Patterns

### 1. Request-Response Pattern

Used for synchronous queries where the sender waits for a response:

```rust
// Example: Getting validator set from Application
pub async fn get_validators(
    application_mailbox: &ApplicationMailbox<PublicKey>
) -> Result<Vec<PublicKey>> {
    let (tx, rx) = oneshot::channel();
    
    application_mailbox
        .send(ApplicationMessage::GetValidators(tx))
        .await?;
        
    let validators = rx.await?;
    Ok(validators)
}
```

### 2. Fire-and-Forget Pattern

Used for asynchronous notifications where no response is expected:

```rust
// Example: Notifying about new block
pub async fn notify_new_block(
    syncer_mailbox: &SyncerMailbox<Scheme, Block>,
    block: Block
) -> Result<()> {
    syncer_mailbox
        .send(SyncerMessage::ReceiveBlock(block))
        .await?;
        
    Ok(())
}
```

### 3. Broadcast Pattern

Used for distributing messages to multiple actors:

```rust
// Example: Broadcasting consensus activity
pub async fn broadcast_activity(
    activity: Activity,
    orchestrator_mailboxes: &[OrchestratorMailbox<Signer, Activity>]
) -> Result<()> {
    let broadcast_futures: Vec<_> = orchestrator_mailboxes
        .iter()
        .map(|mailbox| {
            mailbox.send(OrchestratorMessage::ReceiveActivity(activity.clone()))
        })
        .collect();
        
    futures::future::try_join_all(broadcast_futures).await?;
    Ok(())
}
```

## Actor Supervision and Error Handling

### Supervision Tree

The Engine acts as the root supervisor for all actors:

```rust
impl<E, C, O, S> Engine<E, C, O, S> {
    pub async fn run(&mut self) -> Result<()> {
        // Spawn all actors
        let application_handle = self.spawn_application().await?;
        let finalizer_handle = self.spawn_finalizer().await?;
        let syncer_handle = self.spawn_syncer().await?;
        let orchestrator_handle = self.spawn_orchestrator().await?;
        
        // Monitor actor health
        loop {
            tokio::select! {
                result = &mut application_handle => {
                    error!("Application actor failed: {:?}", result);
                    // Restart application actor
                    self.restart_application().await?;
                },
                result = &mut finalizer_handle => {
                    error!("Finalizer actor failed: {:?}", result);
                    // Restart finalizer actor
                    self.restart_finalizer().await?;
                },
                // Monitor other actors...
                _ = self.context.cancelled() => break,
            }
        }
        
        Ok(())
    }
}
```

### Error Recovery

Each actor implements error recovery strategies:

```rust
impl<E, C, S, PK, SGN, V> Actor<E, C, S, PK, SGN, V> {
    async fn run_with_recovery(&mut self) -> Result<()> {
        let mut error_count = 0;
        const MAX_ERRORS: usize = 10;
        
        loop {
            match self.run_once().await {
                Ok(()) => {
                    error_count = 0; // Reset on success
                },
                Err(e) if error_count < MAX_ERRORS => {
                    warn!("Actor error, retrying: {:?}", e);
                    error_count += 1;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                },
                Err(e) => {
                    error!("Actor failed permanently: {:?}", e);
                    return Err(e);
                }
            }
        }
    }
}
```

## Mailbox Implementation

### Typed Mailboxes

Each actor has a typed mailbox that ensures type safety:

```rust
pub struct Mailbox<T> {
    sender: mpsc::UnboundedSender<T>,
    receiver: mpsc::UnboundedReceiver<T>,
}

impl<T> Mailbox<T> {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        Self { sender, receiver }
    }
    
    pub async fn send(&self, message: T) -> Result<()> {
        self.sender.send(message)
            .map_err(|_| Error::MailboxClosed)?;
        Ok(())
    }
    
    pub async fn recv(&mut self) -> Option<T> {
        self.receiver.recv().await
    }
}
```

### Message Ordering

Summit maintains message ordering guarantees within actor boundaries:

```rust
// Messages from a single sender are processed in order
pub struct OrderedMailbox<T> {
    mailbox: Mailbox<T>,
    sequence_number: u64,
    next_expected: u64,
    buffer: BTreeMap<u64, T>,
}

impl<T> OrderedMailbox<T> {
    pub async fn send_ordered(&self, message: T, seq: u64) -> Result<()> {
        let ordered_message = OrderedMessage { seq, message };
        self.mailbox.send(ordered_message).await
    }
    
    pub async fn recv_ordered(&mut self) -> Option<T> {
        loop {
            // Check if next expected message is buffered
            if let Some(message) = self.buffer.remove(&self.next_expected) {
                self.next_expected += 1;
                return Some(message);
            }
            
            // Wait for new message
            if let Some(ordered_message) = self.mailbox.recv().await {
                if ordered_message.seq == self.next_expected {
                    self.next_expected += 1;
                    return Some(ordered_message.message);
                } else {
                    // Buffer out-of-order message
                    self.buffer.insert(ordered_message.seq, ordered_message.message);
                }
            }
        }
    }
}
```

## Performance Considerations

### Mailbox Sizing

Mailboxes are configured with appropriate buffer sizes:

```rust
// Configuration in node/src/config.rs
pub const MAILBOX_SIZE: usize = 1024;
pub const ORCHESTRATOR_CHANNEL: usize = 512;
pub const FINALIZER_CHANNEL: usize = 256;
pub const SYNCER_CHANNEL: usize = 2048; // Larger for block sync
```

### Message Batching

High-throughput actors use message batching:

```rust
impl<E, B, P, S> Actor<E, B, P, S> {
    async fn process_batch(&mut self) -> Result<()> {
        let mut batch = Vec::with_capacity(32);
        
        // Collect batch of messages
        while batch.len() < 32 {
            match timeout(Duration::from_millis(10), self.mailbox.recv()).await {
                Ok(Some(msg)) => batch.push(msg),
                _ => break, // Timeout or channel closed
            }
        }
        
        // Process entire batch
        for message in batch {
            self.process_message(message).await?;
        }
        
        Ok(())
    }
}
```

### Backpressure Handling

Actors implement backpressure to prevent memory exhaustion:

```rust
pub struct BackpressureMailbox<T> {
    mailbox: Mailbox<T>,
    capacity: usize,
    current_size: Arc<AtomicUsize>,
}

impl<T> BackpressureMailbox<T> {
    pub async fn send_with_backpressure(&self, message: T) -> Result<()> {
        // Wait if mailbox is full
        while self.current_size.load(Ordering::Relaxed) >= self.capacity {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        
        self.current_size.fetch_add(1, Ordering::Relaxed);
        self.mailbox.send(message).await?;
        
        Ok(())
    }
    
    pub async fn recv(&mut self) -> Option<T> {
        let message = self.mailbox.recv().await;
        if message.is_some() {
            self.current_size.fetch_sub(1, Ordering::Relaxed);
        }
        message
    }
}
```

## Testing Actor Systems

### Mock Actors

Testing uses mock actors for isolated testing:

```rust
#[cfg(test)]
pub struct MockApplication {
    responses: HashMap<String, Vec<u8>>,
    received_messages: Vec<ApplicationMessage<PublicKey>>,
}

#[cfg(test)]
impl MockApplication {
    pub fn with_response(mut self, key: &str, response: Vec<u8>) -> Self {
        self.responses.insert(key.to_string(), response);
        self
    }
    
    pub fn received_messages(&self) -> &[ApplicationMessage<PublicKey>] {
        &self.received_messages
    }
}
```

### Actor Integration Tests

Integration tests verify actor interactions:

```rust
#[tokio::test]
async fn test_block_processing_flow() {
    // Setup actors
    let mut application = Application::new(test_config()).await;
    let mut finalizer = Finalizer::new(test_config()).await;
    let mut syncer = Syncer::new(test_config()).await;
    
    // Create test block
    let test_block = create_test_block();
    
    // Send block to syncer
    syncer.mailbox.send(SyncerMessage::ReceiveBlock(test_block.clone())).await?;
    
    // Process messages
    tokio::time::timeout(Duration::from_secs(5), async {
        // Wait for block to be processed through the system
        while !application.has_block(&test_block.hash()) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await?;
    
    // Verify final state
    assert!(application.has_block(&test_block.hash()));
}
```

The actor system provides a robust foundation for Summit's consensus operations with clear separation of concerns, type safety, and fault tolerance.