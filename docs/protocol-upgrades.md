# Protocol Upgrades

Changes to consensus rules on an existing Summit network must activate through a
future epoch-versioned fork mechanism, preserving chain identity and verifiable
history. Replacing genesis files or rolling out incompatible binaries without
coordinated activation is not a supported upgrade path for that network.

This is a pre-mainnet policy decision. The fork mechanism is not implemented;
[issue #448](https://github.com/SeismicSystems/summit/issues/448) tracks its design.

## Current Limitations

[`chain_domain`](../types/src/lib.rs) binds the compile-time `PROTOCOL_VERSION`
and the genesis configuration digest into the domain used for P2P authentication
and consensus signatures. [`verify_checkpoint_chain`](../types/src/checkpoint.rs)
reconstructs that domain using the running binary's version. Bumping the version
alone therefore breaks peering with the old version and verification of
historical finalization certificates, including those in checkpoints. The version
constant does not provide coordinated activation or historical version selection.

Protocol parameter updates can change values that existing consensus code reads.
They cannot introduce new message types, validation rules, or state transitions.
Changes to those rules, including changes needed to support new execution-layer
payloads or Engine API versions, require coordinated protocol activation.

## Requirements for the Future Mechanism

- An agreed schedule of activation epochs and protocol versions, anchored to the
  genesis version.
- Consensus signature domains selected by the message's epoch, preserving the
  original domains for historical certificate and checkpoint verification.
- Binaries that carry the rules needed on both sides of an activation and switch
  to the new rules at the scheduled epoch.
- P2P compatibility during rollout before activation, while retaining rejection
  of peers using incompatible rules.

Schedule governance, wire formats, peer compatibility negotiation, and specific
rule migrations remain design work under issue #448. Compatible binary updates
and parameter changes already supported by existing code do not themselves
require a new fork.
