# High-Throughput Consensus Testing

This module provides sustained transaction load testing for the Summit consensus network. The tests spawn real node processes and flood them with transactions from external clients.

## Quick Start

### Basic High-Throughput Test (1+ minute, 1000+ transactions)

```rust
use system_tests::high_throughput_tests::HighThroughputTest;

// Create test with 4 nodes
let test = HighThroughputTest::new(4).await?;

// Run for 60+ seconds with 1000+ transactions minimum
test.test_sustained_high_throughput(60, 1000).await?;
```

### Concurrent Client Test

```rust
// Test multiple clients sending transactions simultaneously
let test = HighThroughputTest::new(4).await?;

// 10 clients, 200 transactions each = 2000 total
test.test_concurrent_client_load(10, 200).await?;
```

## Available Test Methods

### `test_sustained_high_throughput(duration_secs, min_transactions)`
- Runs continuous transaction load for the specified duration
- Ensures at least `min_transactions` are sent and included in blocks
- Uses batched sending with multiple external clients
- Verifies consensus is maintained throughout the test
- Reports transaction rates and inclusion percentages

### `test_concurrent_client_load(num_clients, transactions_per_client)`
- Spawns multiple concurrent external clients
- Each client sends the specified number of transactions
- Tests the system's ability to handle parallel transaction submission
- Verifies all transactions are processed and reach consensus

## Running Tests Manually

Since these tests require real node processes, they're marked with `#[ignore]`. To run them:

```bash
# Quick test (recommended for initial verification)
RUST_LOG=info cargo test -p system-tests sustained_high_throughput -- --ignored --nocapture

# Concurrent client test
RUST_LOG=info cargo test -p system-tests concurrent_client_load -- --ignored --nocapture

# All real integration tests (includes high-throughput)
RUST_LOG=info cargo test -p system-tests -- --ignored --nocapture
```

## Test Scenarios

### 1-Minute Load Test (meets requirements)
- **Duration**: 60+ seconds minimum
- **Transactions**: 1000+ minimum  
- **Purpose**: Validates sustained throughput capability
- **Verification**: ≥80% transaction inclusion rate, consensus maintained

### Extended Load Test
- **Duration**: 120+ seconds
- **Transactions**: 2000+ minimum
- **Purpose**: Tests longer-term stability
- **Verification**: Higher throughput over extended period

### Extreme Load Test
- **Duration**: 300+ seconds (5 minutes)
- **Transactions**: 5000+ minimum
- **Purpose**: Stress tests system limits
- **Verification**: System remains stable under extreme load

## Test Flow

1. **Setup Phase**: Spawn real Reth nodes and Summit consensus processes
2. **Load Generation Phase**: Send transactions continuously from external clients
3. **Monitoring Phase**: Track transaction rates and node status
4. **Verification Phase**: Confirm transactions are included in blocks
5. **Consensus Check**: Verify all nodes agree on block content

## Key Features

- **Real Process Testing**: Uses actual Reth node binaries
- **External Client Simulation**: Transactions come from external accounts (not consensus nodes)
- **Genesis Integration**: Uses pre-funded accounts from `testnet/dev.json`
- **Comprehensive Verification**: Checks transaction inclusion, consensus, and block consistency
- **Performance Metrics**: Reports transaction rates, inclusion rates, and timing

## Prerequisites

- Reth binary available in PATH
- Must run from project root directory
- Access to `testnet/dev.json` for funded accounts
- Available network ports for node communication
- Sufficient system resources for multiple node processes

## Expected Results

✅ **Duration**: Test runs for at least the specified minimum time  
✅ **Transaction Count**: At least the minimum number of transactions are sent  
✅ **Inclusion Rate**: ≥80% of transactions are included in blocks  
✅ **Consensus**: All nodes maintain consistent block hashes throughout  
✅ **Performance**: System handles sustained load without degradation

## Troubleshooting

**Build Errors**: Ensure you're running from the project root and have access to genesis files

**Node Startup Failures**: Check that Reth is installed and available in PATH

**Low Transaction Inclusion**: May indicate consensus issues or insufficient block space

**Consensus Failures**: Suggests network partitions or Byzantine behavior

**Performance Issues**: System may be under-resourced for the specified load

## Implementation Details

The high-throughput tests use:
- **Batched Transaction Sending**: Groups transactions for efficient submission
- **Multiple Client Accounts**: Distributes load across funded genesis accounts
- **Concurrent Execution**: Sends transactions in parallel to maximize throughput
- **Comprehensive Monitoring**: Tracks progress and provides detailed logging
- **Robust Verification**: Scans all blocks to confirm transaction inclusion