//! Standard variant implementation for the syncer.
//!
//! The standard variant broadcasts complete blocks to all peers. Each validator
//! receives the full block directly from the proposer or via gossip.

mod variant;
pub use variant::Standard;
