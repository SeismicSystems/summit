//! Marshal variant and buffer traits.
//!
//! These abstractions allow the syncer actor to work with different block
//! dissemination strategies:
//!
//! - [`Variant`]: Describes the types used by a marshal variant
//! - [`Buffer`]: Abstracts over block dissemination strategies
//!
//! The [`Variant`] trait expects a 1:1 mapping between the [`Variant::Commitment`] and the
//! block digest, with the commitment being a superset of the digest. The commitment may
//! contain extra information for optimized retrieval, though the digest must be extractable
//! from the commitment for lookup purposes.

use commonware_codec::{Codec, Read};
use commonware_consensus::{Block, types::Round};
use commonware_cryptography::{Digest, Digestible, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;
use std::future::Future;

/// A marker trait describing the types used by a variant of the syncer.
pub trait Variant: Clone + Send + Sync + 'static {
    /// The working block type, supporting the consensus commitment.
    ///
    /// Must be convertible to `StoredBlock` via `Into` for archival.
    type Block: Block<Digest = <Self::ApplicationBlock as Digestible>::Digest>
        + Into<Self::StoredBlock>
        + Clone;

    /// The application block type.
    type ApplicationBlock: Block + Clone;

    /// The type of block stored in the archive.
    ///
    /// Must be convertible back to the working block type via `Into`.
    type StoredBlock: Block<Digest = <Self::Block as Digestible>::Digest>
        + Into<Self::Block>
        + Clone
        + Codec<Cfg = <Self::ApplicationBlock as Read>::Cfg>;

    /// The [`Digest`] type used by consensus.
    type Commitment: Digest;

    /// Computes the consensus commitment for a block.
    ///
    /// Together with [`Variant::commitment_to_inner`], implementations must satisfy:
    /// `commitment_to_inner(commitment(block)) == block.digest()`.
    fn commitment(block: &Self::Block) -> Self::Commitment;

    /// Extracts the block digest from a consensus commitment.
    fn commitment_to_inner(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest;

    /// Returns the parent commitment referenced by `block`.
    fn parent_commitment(block: &Self::Block) -> Self::Commitment;

    /// Returns the codec configuration used to decode [`Self::Block`] received over the wire.
    ///
    /// The returned configuration may bind `expected` so that decoding rejects
    /// blocks that do not match the expected commitment.
    fn block_cfg(
        block_cfg: &<Self::ApplicationBlock as Read>::Cfg,
        expected: Self::Commitment,
    ) -> <Self::Block as Read>::Cfg;

    /// Converts a working block to an application block.
    fn into_inner(block: Self::Block) -> Self::ApplicationBlock;
}

/// A buffer for block storage and retrieval, abstracting over different
/// dissemination strategies.
///
/// Lookup operations come in two forms:
/// - By digest: Simple lookup using only the block hash
/// - By commitment: Lookup using the full consensus commitment
pub trait Buffer<V: Variant>: Clone + Send + Sync + 'static {
    /// The public key type used to identify peers.
    type PublicKey: PublicKey;

    /// Attempt to find a block by its digest.
    fn find_by_digest(
        &self,
        digest: <V::Block as Digestible>::Digest,
    ) -> impl Future<Output = Option<V::Block>> + Send;

    /// Attempt to find a block by its commitment.
    fn find_by_commitment(
        &self,
        commitment: V::Commitment,
    ) -> impl Future<Output = Option<V::Block>> + Send;

    /// Subscribe to a block's availability by its digest.
    ///
    /// Returns a receiver that will resolve when the block becomes available.
    /// If the block is already cached, the receiver may resolve immediately.
    /// Returns `None` when the buffer cannot provide availability notifications.
    fn subscribe_by_digest(
        &self,
        digest: <V::Block as Digestible>::Digest,
    ) -> Option<oneshot::Receiver<V::Block>>;

    /// Subscribe to a block's availability by its commitment.
    ///
    /// Returns a receiver that will resolve when the block becomes available.
    /// If the block is already cached, the receiver may resolve immediately.
    /// Returns `None` when the buffer cannot provide availability notifications.
    fn subscribe_by_commitment(
        &self,
        commitment: V::Commitment,
    ) -> Option<oneshot::Receiver<V::Block>>;

    /// Notify the buffer that a block has been finalized.
    fn finalized(&self, commitment: V::Commitment);

    /// Send a block to peers.
    fn send(&self, round: Round, block: V::Block, recipients: Recipients<Self::PublicKey>);
}
