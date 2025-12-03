# Summit Documentation

This documentation is designed to provide auditors and developers with a comprehensive understanding of the Summit consensus client architecture, dependencies, and implementation details.

## Documentation Structure

- **[Architecture Overview](./architecture.md)** - High-level system design and component interactions
- **[Commonware Dependencies](./commonware-dependencies.md)** - Detailed analysis of Commonware library usage
- **[Engine API Integration](./engine-api-integration.md)** - Communication patterns with execution clients (Reth)
- **[Security Model](./security-model.md)** - Cryptographic primitives and security considerations
- **[Actor System](./actor-system.md)** - Actor-based architecture and message passing patterns

## Quick Reference

### Key Components
- **Consensus Layer**: Implements Simplex protocol via Commonware
- **Execution Integration**: Engine API communication with Reth/Geth
- **Network Layer**: P2P networking and validator discovery
- **Storage Layer**: Block and consensus state persistence
- **RPC Layer**: External API for clients

### Critical Paths
1. **Block Production**: `finalizer` → `engine_client` → execution client
2. **Block Validation**: `syncer` → `engine_client` → execution client  
3. **Consensus**: `orchestrator` → Commonware consensus primitives
4. **Network Sync**: `syncer` → Commonware P2P → remote validators

### Security Boundaries
- **Cryptographic**: BLS12-381 signatures, Ed25519 for networking
- **Network**: Authenticated P2P with peer verification
- **Execution**: Isolation via Engine API, no direct EVM access
- **Storage**: Immutable consensus data with cryptographic verification

## For Auditors

When auditing Summit, focus on these critical areas:

1. **Consensus Safety**: Review Simplex protocol implementation in `finalizer/` and `orchestrator/`
2. **Engine API Security**: Examine execution client communication in `types/src/engine_client.rs`
3. **Cryptographic Implementation**: Verify key management and signature schemes in `types/src/keystore.rs`
4. **Network Security**: Analyze P2P authentication and message validation
5. **State Consistency**: Review storage patterns and state transitions

## External Dependencies

- **Commonware**: Consensus protocol, cryptography, and networking primitives
- **Alloy**: Ethereum types and Engine API client
- **Tokio**: Async runtime and utilities
- **OpenSSL/Ring**: Cryptographic backends (via Commonware)

Summit does not implement custom cryptography or consensus algorithms
