# Summit Consensus Tests

This directory contains integration tests for the Summit consensus client organized into separate crates.

## Test Structure

- `test_utils/` - Shared test utilities and helper functions
- `consensus_tests/` - Core consensus mechanism tests 
- `failure_tests/` - Byzantine behavior and failure scenario tests

## Running Tests

### All Integration Tests

To run all integration tests:

```bash
# Run all test crates
cargo test --workspace --exclude summit-types --exclude summit-syncer --exclude summit-application --exclude node

# Or run each test crate individually
cargo test -p consensus-tests
cargo test -p failure-tests
```

### Unit Tests Only

To run only unit tests for individual crates:

```bash
# Types crate tests
cargo test -p summit-types

# Syncer crate tests  
cargo test -p summit-syncer

# Application crate tests
cargo test -p summit-application
```

### Specific Test Groups

#### Consensus Mechanism Tests
Tests core consensus algorithms, leader election, and view changes:

```bash
cargo test -p consensus-tests consensus_integration
```

#### Multi-Node Network Tests
Tests multi-node setups, network partitions, and node failures:

```bash
cargo test -p consensus-tests multi_node_tests
```

#### Byzantine Failure Tests
Tests Byzantine behaviors and failure scenarios:

```bash
cargo test -p failure-tests byzantine_scenarios
```

### Test Configuration

Tests use the existing testnet infrastructure:

- Node configuration based on `testnet/` directory structure
- Genesis configuration from `example_genesis.toml`
- Pre-generated keys from `testnet/node*/key.pem`
- Temporary storage directories created per test

### Performance Tests

Some tests may take longer to complete as they simulate real consensus scenarios:

```bash
# Run with longer timeout for consensus tests
cargo test -p consensus-tests -- --test-threads=1 --timeout=60
```

### Debugging Tests

To see detailed logging during test execution:

```bash
RUST_LOG=debug cargo test -p consensus-tests -- --nocapture
```

## Test Patterns

### Test Naming Convention

Tests follow a clear naming pattern:
- `test_[component]_[scenario]_[expected_outcome]`
- Example: `test_consensus_leader_election_succeeds`
- Example: `test_network_partition_recovery_works`

### Byzantine Failure Testing

The failure tests include scenarios for:
- **Network Partitions** - Nodes isolated or split into groups
- **Silent Nodes** - Byzantine nodes that stop participating
- **Double Voting** - Byzantine nodes that vote for multiple blocks
- **Mixed Failures** - Combinations of different failure types

### Test Utilities

The `test_utils` crate provides:
- `TestContext` - Manages test environment setup
- `generate_test_keys()` - Creates cryptographic keys for test validators
- `create_test_genesis()` - Generates test genesis configuration
- `create_test_block()` - Creates valid test blocks
- `wait_for_condition()` - Async condition waiting helper
- Failure scenario builders for Byzantine behavior testing

## Contributing

When adding new tests:

1. Use the existing test utilities in `test_utils/`
2. Follow the naming conventions
3. Keep tests focused on single scenarios
4. Add appropriate timeout handling for async operations
5. Include both positive and negative test cases
6. Update this README when adding new test categories