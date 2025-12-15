# Actor System Architecture

Summit implements an actor-based architecture where independent components communicate by passing typed messages. This document details the actor system design, message flows, and coordination patterns.

## Actor Model Overview

Summit's architecture follows the actor model with these key principles:

- **Isolation**: Each actor maintains its own state and memory
- **Asynchronous**: All actors communicate through non-blocking messages
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

**Purpose**: Handles block production, validation, and finalization

**Key Responsibilities:**
- Propose blocks when selected as leader
- Validate blocks received from network
- Coordinate with execution client via Engine API
- Maintain block cache for pending/finalized blocks

### 2. Finalizer Actor (`finalizer/src/actor.rs`)

**Purpose**: Manages consensus state, validator set, and staking logic

**Key Responsibilities:**
- Maintain current validator set and staking information
- Process validator additions/removals based on execution layer events
- Manage consensus state transitions
- Handle withdrawal processing
- Create and verify checkpoints

### 3. Syncer Actor (`syncer/src/actor.rs`)

**Purpose**: Manages block synchronization, caching, and network state

**Key Responsibilities:**
- Receive and cache blocks from network
- Resolve missing blocks through backfill
- Broadcast verified blocks to peers
- Maintain local block cache
- Coordinate synchronization with peers
- Push notarized and finalized blocks to the Finalizer Actor

### 4. Orchestrator Actor (`orchestrator/src/actor.rs`)

**Purpose**: Coordinates consensus protocol execution and activity management

**Key Responsibilities:**
- Epoch transition management
- Simplex engine lifecycle management
- Network channel multiplexing
- Epoch boundary block synchronization

## Actor Supervision and Error Handling

### Supervision Tree

The Engine acts as the root supervisor for all actors, meaning it can restart them

### Error Recovery

Each actor implements error recovery strategies

## Mailbox Implementation

Each actor has a typed mailbox that ensures type safety.

## Performance Considerations

### Message Batching

High-throughput actors use message batching:

### Backpressure Handling

Actors implement backpressure to prevent memory exhaustion
