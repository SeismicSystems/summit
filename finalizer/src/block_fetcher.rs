/*
Requests the finalized blocks (in order) from the orchestrator, sends them to the finalizer to be executed,
waits for confirmation that the finalizer has processed the block.

Gets the highest height for which the application has processed from the finalizer. This allows resuming
processing from the last processed height after a restart.
*/

use commonware_cryptography::Committable as _;
use futures::{
    SinkExt as _, StreamExt as _,
    channel::{mpsc, oneshot},
};
use summit_syncer::Orchestrator;
use summit_types::{BlockEnvelope, utils::is_last_block_of_epoch};
use tracing::{debug, error};
pub struct BlockFetcher {
    // Orchestrator that stores the finalized blocks.
    orchestrator: Orchestrator,

    // Notifier to indicate that the finalized blocks have been updated and should be re-queried.
    notifier_rx: mpsc::Receiver<()>,

    // Number of blocks per epoch
    epoch_num_blocks: u64,

    // The lowest height from which to begin syncing
    sync_height: u64,

    finalizer_mailbox: mpsc::Sender<(BlockEnvelope, oneshot::Sender<()>)>,
}

impl BlockFetcher {
    /// Initialize the finalizer.
    pub fn new(
        orchestrator: Orchestrator,
        notifier_rx: mpsc::Receiver<()>,
        epoch_num_blocks: u64,
        sync_height: u64,
    ) -> (Self, mpsc::Receiver<(BlockEnvelope, oneshot::Sender<()>)>) {
        let (finalizer_mailbox, finalized_block_envelopes) = mpsc::channel(100); // todo(dalton) take channel size from a config
        (
            Self {
                orchestrator,
                notifier_rx,
                epoch_num_blocks,
                sync_height,
                finalizer_mailbox,
            },
            finalized_block_envelopes,
        )
    }

    /// Run the block_fetcher, which continuously fetches and sends finalized blocks to finalizer.
    pub async fn run(mut self) {
        let mut latest = self.sync_height;

        // The main loop to process finalized blocks. This loop will hot-spin until a block is
        // available, at which point it will process it and continue. If a block is not available,
        // it will request a repair and wait for a notification of an update before retrying.
        loop {
            // The next height to process is the next height after the last processed height.
            let height = latest + 1;

            let (block, finalized) = if is_last_block_of_epoch(height, self.epoch_num_blocks) {
                self.orchestrator.get_with_finalized(height).await
            } else {
                (self.orchestrator.get(height).await, None)
            };

            // Attempt to get the next block from the orchestrator.
            if let Some(block) = block {
                // Sanity-check that the block height is the one we expect.
                assert_eq!(block.height(), height, "block height mismatch");

                // Send the block to the finalizer.
                //
                // After an unclean shutdown (where the finalizer metadata is not synced after some
                // height is processed by the application), it is possible that the application may
                // be asked to process a block it has already seen (which it can simply ignore).
                let commitment = block.commitment();
                let envelope = BlockEnvelope { block, finalized };
                let (tx, rx) = oneshot::channel();
                self.finalizer_mailbox
                    .send((envelope, tx))
                    .await
                    .expect("BlockFetcher->Finalizer channel closed");
                rx.await.expect("Unable to get response from finalizer");
                // Record that we have processed up through this height.
                latest = height;

                // Notify the orchestrator that the block has been processed.
                self.orchestrator.processed(height, commitment).await;

                // Loop again without waiting for a notification (there may be more to process).
                continue;
            }

            // We've reached a height at which we have no (finalized) block.
            // It may be the case that the block is not finalized yet, or that there is a gap.
            // Notify the orchestrator that we're trying to access this block.
            self.orchestrator.repair(height).await;

            // Wait for a notification from the orchestrator that new blocks are available.
            debug!(height, "waiting to index finalized block");
            let Some(()) = self.notifier_rx.next().await else {
                error!("orchestrator closed, shutting down");
                return;
            };
        }
    }
}
