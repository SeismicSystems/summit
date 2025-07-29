# Summit Consensus Tests

This directory contains integration tests for the Summit consensus client organized into separate crates.

## Test Structure

- `test_utils/` - Shared test utilities and helper functions
- `consensus_tests/` - Core consensus mechanism tests 
- `failure_tests/` - Byzantine behavior and failure scenario tests
- `real_integration/` - Multi-process integration tests with real node binaries

## 🧪 Test Command Reference

### **Basic Test Commands**

```bash
# Run all tests (unit + integration)
cargo test

# Run only library tests (excludes integration tests)
cargo test --lib

# Run tests with output (shows println! statements)
cargo test -- --nocapture

# Run tests in parallel (default) or single-threaded
cargo test -- --test-threads=1
```

### **Integration Test Commands**

```bash
# Run all integration tests
cargo test -p consensus-tests
cargo test -p failure-tests

# Run real integration tests (spawns actual node processes)
cargo test -p real-integration -- --ignored

# Run specific integration test files
cargo test --test consensus_integration
cargo test --test multi_node_tests

# Run a specific integration test function
cargo test -p consensus-tests test_single_node_basic_setup
cargo test -p consensus-tests test_bft_node_count_boundary
cargo test -p real-integration test_multi_reth_startup -- --ignored
```

### **Per-Crate Test Commands**

```bash
# Core crates (your main implementation)
cargo test -p summit-types
cargo test -p summit-syncer  
cargo test -p summit-application

# Test infrastructure
cargo test -p test-utils
cargo test -p failure-tests
cargo test -p real-integration

# Node binary tests
cargo test -p summit
```

### **Specific Test Categories**

```bash
# Unit tests only (excludes integration tests)
cargo test --lib -p summit-types -p summit-syncer -p summit-application

# Test specific modules within a crate
cargo test -p summit-types genesis::tests
cargo test -p summit-types block::test
cargo test -p summit-syncer key::tests

# Test specific functions
cargo test -p summit-types test_genesis_validator_count
cargo test -p summit-syncer test_multi_index_ordering_semantics
```

### **Development & Debugging Commands**

```bash
# Run tests with detailed output
cargo test -- --nocapture --test-threads=1

# Show test execution time
cargo test -- --report-time

# Run only failing tests (after a failure)
cargo test --workspace --lib

# Run tests with Rust backtrace on failures
RUST_BACKTRACE=1 cargo test

# Run tests with full backtrace
RUST_BACKTRACE=full cargo test
```

### **Performance & CI Commands**

```bash
# Fast compilation for testing
cargo test --profile test

# Run tests without building docs
cargo test --workspace --exclude docs

# Check that tests compile without running
cargo test --no-run
```

### **Recommended Development Workflow**

```bash
# 1. Quick unit test check (fast)
cargo test --lib

# 2. Full test suite (comprehensive)
cargo test

# 3. Focus on specific area you're working on
cargo test -p summit-types  # if working on types
cargo test -p summit-syncer # if working on consensus

# 4. Integration tests after major changes
cargo test -p consensus-tests
cargo test -p failure-tests

# 5. Real multi-process tests (requires node binaries)
cargo test -p real-integration -- --ignored

# 6. Debug specific failing test
cargo test test_name -- --nocapture --test-threads=1
```

## Test Structure Overview

Your test suite is organized as:

```
tests/
├── test_utils/           # Shared test utilities
├── consensus_tests/      # Integration tests
│   ├── src/integration.rs    # Basic integration tests  
│   └── src/multi_node.rs     # Multi-node test scenarios
└── failure_tests/        # Failure scenario tests (placeholder)

# Plus unit tests in each main crate:
types/src/           # Block, Genesis tests
syncer/src/          # Coordinator, Key, Ingress tests  
application/src/     # Config tests
```

## Test Categories

### Unit Tests
- **Types crate**: Block creation, serialization, genesis configuration
- **Syncer crate**: Coordinator p2p implementation, key ordering, ingress messaging
- **Application crate**: Configuration management and validation

### Integration Tests
- **Basic setup tests**: Multi-node context creation, genesis block generation
- **BFT boundary tests**: Testing 3f+1 node requirements for different fault tolerance levels
- **Test infrastructure**: Temporary directory management, test isolation

### Test Utilities
The `test_utils` crate provides:
- `TestContext` - Manages test environment setup
- `generate_test_keys()` - Creates cryptographic keys for test validators
- `create_test_genesis()` - Generates test genesis configuration
- `create_test_block()` - Creates valid test blocks
- `wait_for_condition()` - Async condition waiting helper

## Real Integration Tests

The `real_integration/` crate contains tests that spawn actual node processes to test distributed consensus:

### Key Features
- **External Client Simulation**: Tests simulate external clients (not consensus nodes) sending transactions
- **Multi-Process Testing**: Spawns real Reth node binaries and Summit consensus processes  
- **Genesis File Integration**: Uses pre-funded accounts from `testnet/dev.json`
- **Consensus Verification**: Verifies that all nodes reach agreement on block hashes and transaction inclusion

### Running Real Integration Tests
```bash
# Run all real integration tests (requires node binaries)
cargo test -p real-integration -- --ignored

# Test external clients sending transactions to consensus network
cargo test -p real-integration test_external_clients_to_consensus_network -- --ignored

# Test that clients can send to any node and still reach consensus
cargo test -p real-integration test_client_node_agnostic_consensus -- --ignored
```

### Prerequisites
- Reth binary available in PATH
- Must be run from project root directory (needs access to `testnet/dev.json`)
- Available network ports for node communication
- Sufficient disk space for temporary node data

### External Client Testing Philosophy
These tests simulate the real-world scenario where:
1. **External clients** (users, applications) send transactions to consensus nodes
2. **Consensus nodes** receive transactions via JSON-RPC and include them in blocks
3. **All nodes** must agree on the same block content and ordering
4. **Transaction propagation** works regardless of which node receives the transaction

This accurately reflects how blockchain networks operate, where external entities interact with the consensus layer through well-defined interfaces.

## Contributing

When adding new tests:

1. Use the existing test utilities in `test_utils/`
2. Follow the naming conventions
3. Keep tests focused on single scenarios
4. Add appropriate timeout handling for async operations
5. Include both positive and negative test cases
6. For real integration tests, ensure external clients (not nodes) send transactions
7. Update this README when adding new test categories