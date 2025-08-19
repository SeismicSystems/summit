use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, Error, Read, Write};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::store::{self, Store};
use commonware_storage::translator::TwoCap;
use commonware_utils::sequence::FixedBytes;
pub use store::Config;

const HEAD_KEY: [u8; 8] = 0u64.to_be_bytes();
const TAIL_KEY: [u8; 8] = 1u64.to_be_bytes();

pub struct PersistentQueue<E: Clock + Storage + Metrics, V: Codec + Read<Cfg = ()>> {
    // Single store for both pointers and values
    store: Store<E, FixedBytes<8>, Value<V>, TwoCap>,
}

impl<E: Clock + Storage + Metrics, V: Codec + Read<Cfg = ()>> PersistentQueue<E, V> {
    // Helper methods to extract pointer values
    async fn get_head_value(&self) -> u64 {
        let head_key = FixedBytes::new(HEAD_KEY);
        let head_pointer = self
            .store
            .get(&head_key)
            .await
            .expect("failed to get head")
            .expect("head should be initialized");

        if let Value::Pointer(ptr) = head_pointer {
            u64::from_be_bytes(ptr.as_ref().try_into().expect("8 bytes"))
        } else {
            panic!("head should be a pointer");
        }
    }

    async fn get_tail_value(&self) -> u64 {
        let tail_key = FixedBytes::new(TAIL_KEY);
        let tail_pointer = self
            .store
            .get(&tail_key)
            .await
            .expect("failed to get tail")
            .expect("tail should be initialized");

        if let Value::Pointer(ptr) = tail_pointer {
            u64::from_be_bytes(ptr.as_ref().try_into().expect("8 bytes"))
        } else {
            panic!("tail should be a pointer");
        }
    }

    async fn update_head_pointer(&mut self, value: u64) {
        let head_key = FixedBytes::new(HEAD_KEY);
        self.store
            .update(
                head_key,
                Value::Pointer(FixedBytes::new(value.to_be_bytes())),
            )
            .await
            .expect("failed to update head pointer");
    }

    async fn update_tail_pointer(&mut self, value: u64) {
        let tail_key = FixedBytes::new(TAIL_KEY);
        self.store
            .update(
                tail_key,
                Value::Pointer(FixedBytes::new(value.to_be_bytes())),
            )
            .await
            .expect("failed to update tail pointer");
    }

    pub async fn new(context: E, cfg: Config<TwoCap, ()>) -> Self {
        let mut store = Store::<_, FixedBytes<8>, Value<V>, TwoCap>::init(context, cfg)
            .await
            .expect("failed to initialize store");

        // Initialize head and tail pointers if they don't exist
        let head_key = FixedBytes::new(HEAD_KEY);
        let tail_key = FixedBytes::new(TAIL_KEY);

        if store
            .get(&head_key)
            .await
            .expect("failed to get head")
            .is_none()
        {
            store
                .update(
                    head_key,
                    Value::Pointer(FixedBytes::new(2u64.to_be_bytes())),
                )
                .await
                .expect("failed to initialize head pointer");
        }

        if store
            .get(&tail_key)
            .await
            .expect("failed to get tail")
            .is_none()
        {
            store
                .update(
                    tail_key,
                    Value::Pointer(FixedBytes::new(2u64.to_be_bytes())),
                )
                .await
                .expect("failed to initialize tail pointer");
        }

        Self { store }
    }

    pub async fn push(&mut self, value: V) {
        let tail_value = self.get_tail_value().await;

        // Store the value at the tail position
        let value_key = FixedBytes::new(tail_value.to_be_bytes());
        self.store
            .update(value_key, Value::Value(value))
            .await
            .expect("failed to store value");

        // Increment tail pointer
        self.update_tail_pointer(tail_value + 1).await;

        self.store.commit().await.expect("failed to commit changes");
    }

    pub async fn pop(&mut self) -> Option<V> {
        let head_value = self.get_head_value().await;
        let tail_value = self.get_tail_value().await;

        // Check if queue is empty
        if head_value == tail_value {
            return None;
        }

        let value_key = FixedBytes::new(head_value.to_be_bytes());
        if let Some(Value::Value(value)) = self
            .store
            .get(&value_key)
            .await
            .expect("failed to get value")
        {
            // Remove the value from storage
            self.store
                .delete(value_key)
                .await
                .expect("failed to delete value");

            // Increment head pointer
            let new_head = head_value + 1;

            // If queue becomes empty after this pop, reset pointers to 2
            if new_head == tail_value {
                self.update_head_pointer(2).await;
                self.update_tail_pointer(2).await;
            } else {
                self.update_head_pointer(new_head).await;
            }

            self.store.commit().await.expect("failed to commit changes");
            Some(value)
        } else {
            None
        }
    }

    pub async fn is_empty(&self) -> bool {
        let head_value = self.get_head_value().await;
        let tail_value = self.get_tail_value().await;
        head_value == tail_value
    }

    pub async fn len(&self) -> usize {
        let head_value = self.get_head_value().await;
        let tail_value = self.get_tail_value().await;
        (tail_value - head_value) as usize
    }

    pub async fn peek(&self) -> Option<V>
    where
        V: Clone,
    {
        let head_value = self.get_head_value().await;
        let tail_value = self.get_tail_value().await;

        // Check if queue is empty
        if head_value == tail_value {
            return None;
        }

        // Use get() to peek without removing
        let value_key = FixedBytes::new(head_value.to_be_bytes());
        if let Some(Value::Value(value)) = self
            .store
            .get(&value_key)
            .await
            .expect("failed to get value")
        {
            Some(value.clone())
        } else {
            None
        }
    }
}

enum Value<V: Codec> {
    Pointer(FixedBytes<8>),
    Value(V),
}

impl<V> EncodeSize for Value<V>
where
    V: Codec,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            // +1 for the type tag byte
            Self::Pointer(fb) => fb.encode_size(),
            Self::Value(v) => v.encode_size(),
        }
    }
}

impl<V> Read for Value<V>
where
    V: Codec + Read<Cfg = ()>,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let value_type = buf.get_u8();
        match value_type {
            0x00 => Ok(Self::Pointer(FixedBytes::<8>::read_cfg(buf, &())?)),
            0x01 => Ok(Self::Value(V::read_cfg(buf, &())?)),
            byte => Err(Error::InvalidVarint(byte as usize)),
        }
    }
}

impl<V> Write for Value<V>
where
    V: Codec,
{
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Pointer(fb) => {
                buf.put_u8(0x00);
                fb.write(buf);
            }
            Self::Value(v) => {
                buf.put_u8(0x01);
                v.write(buf);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, deterministic::Runner};

    async fn create_test_queue_with_context<E: Clock + Storage + Metrics>(
        partition: &str,
        context: E,
    ) -> PersistentQueue<E, u32> {
        use commonware_runtime::buffer::PoolRef;
        use commonware_utils::{NZU64, NZUsize};

        let config = Config {
            log_journal_partition: format!("{}-log", partition),
            log_write_buffer: NZUsize!(64 * 1024),
            log_compression: None,
            log_codec_config: (),
            log_items_per_section: NZU64!(4),
            locations_journal_partition: format!("{}-locations", partition),
            locations_items_per_blob: NZU64!(4),
            translator: TwoCap,
            buffer_pool: PoolRef::new(NZUsize!(77), NZUsize!(9)),
        };
        PersistentQueue::new(context, config).await
    }

    #[test]
    fn test_new_queue_is_empty() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(1);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let queue = create_test_queue_with_context("test_new", context).await;

            assert!(queue.is_empty().await);
            assert_eq!(queue.len().await, 0);
        });
    }

    #[test]
    fn test_push_single_item() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(2);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_push_single", context).await;

            queue.push(42).await;

            assert!(!queue.is_empty().await);
            assert_eq!(queue.len().await, 1);
        });
    }

    #[test]
    fn test_push_pop_single_item() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(3);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_push_pop_single", context).await;

            queue.push(42).await;
            let popped = queue.pop().await;

            assert_eq!(popped, Some(42));
            assert!(queue.is_empty().await);
            assert_eq!(queue.len().await, 0);
        });
    }

    #[test]
    fn test_push_pop_multiple_items() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(4);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_push_pop_multiple", context).await;

            // Push multiple items
            queue.push(1).await;
            queue.push(2).await;
            queue.push(3).await;

            assert_eq!(queue.len().await, 3);

            // Pop them in FIFO order
            assert_eq!(queue.pop().await, Some(1));
            assert_eq!(queue.len().await, 2);

            assert_eq!(queue.pop().await, Some(2));
            assert_eq!(queue.len().await, 1);

            assert_eq!(queue.pop().await, Some(3));
            assert_eq!(queue.len().await, 0);
            assert!(queue.is_empty().await);
        });
    }

    #[test]
    fn test_pop_empty_queue() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(5);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_pop_empty", context).await;

            // Pop from empty queue should return None
            let popped = queue.pop().await;
            assert_eq!(popped, None);

            // Queue should still be empty
            assert!(queue.is_empty().await);
            assert_eq!(queue.len().await, 0);
        });
    }

    #[test]
    fn test_pointer_reset_on_empty() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(6);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_pointer_reset", context).await;

            // Push some items to advance pointers
            queue.push(10).await;
            queue.push(20).await;
            queue.push(30).await;

            // Pop all items - this should reset pointers to 2
            assert_eq!(queue.pop().await, Some(10));
            assert_eq!(queue.pop().await, Some(20));
            assert_eq!(queue.pop().await, Some(30)); // This should trigger pointer reset

            // Queue should be empty
            assert!(queue.is_empty().await);
            assert_eq!(queue.len().await, 0);

            // Push new item should start from 2 again
            queue.push(40).await;
            assert_eq!(queue.len().await, 1);
            assert_eq!(queue.pop().await, Some(40));
        });
    }

    #[test]
    fn test_peek_empty_queue() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(7);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let queue = create_test_queue_with_context("test_peek_empty", context).await;

            // Peek empty queue should return None
            assert_eq!(queue.peek().await, None);
            assert!(queue.is_empty().await);
            assert_eq!(queue.len().await, 0);
        });
    }

    #[test]
    fn test_peek_single_item() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(8);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_peek_single", context).await;

            queue.push(42).await;

            // Peek should return the item
            assert_eq!(queue.peek().await, Some(42));
            // Queue should remain unchanged
            assert!(!queue.is_empty().await);
            assert_eq!(queue.len().await, 1);

            // Multiple peeks should return same value
            assert_eq!(queue.peek().await, Some(42));
            assert_eq!(queue.peek().await, Some(42));
            assert_eq!(queue.len().await, 1);
        });
    }

    #[test]
    fn test_peek_multiple_items() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(9);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_peek_multiple", context).await;

            queue.push(1).await;
            queue.push(2).await;
            queue.push(3).await;

            // Peek should return first item (FIFO)
            assert_eq!(queue.peek().await, Some(1));
            assert_eq!(queue.len().await, 3);

            // Multiple peeks should return same value
            assert_eq!(queue.peek().await, Some(1));
            assert_eq!(queue.peek().await, Some(1));
            assert_eq!(queue.len().await, 3);
        });
    }

    #[test]
    fn test_peek_pop_consistency() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(10);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue =
                create_test_queue_with_context("test_peek_pop_consistency", context).await;

            queue.push(100).await;
            queue.push(200).await;

            // Peek and pop should return same value
            assert_eq!(queue.peek().await, Some(100));
            assert_eq!(queue.pop().await, Some(100));

            // Next peek should return next item
            assert_eq!(queue.peek().await, Some(200));
            assert_eq!(queue.pop().await, Some(200));

            // Queue should be empty
            assert_eq!(queue.peek().await, None);
            assert_eq!(queue.pop().await, None);
            assert!(queue.is_empty().await);
        });
    }

    #[test]
    fn test_peek_after_operations() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(11);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_peek_after_ops", context).await;

            // Initial peek on empty queue
            assert_eq!(queue.peek().await, None);

            // Push and peek
            queue.push(10).await;
            assert_eq!(queue.peek().await, Some(10));

            // Pop and peek (should be None)
            assert_eq!(queue.pop().await, Some(10));
            assert_eq!(queue.peek().await, None);

            // Push multiple, peek first
            queue.push(20).await;
            queue.push(30).await;
            assert_eq!(queue.peek().await, Some(20));

            // Pop first, peek should show next
            assert_eq!(queue.pop().await, Some(20));
            assert_eq!(queue.peek().await, Some(30));

            // Pop last, peek should be None
            assert_eq!(queue.pop().await, Some(30));
            assert_eq!(queue.peek().await, None);
        });
    }

    #[test]
    fn test_persistence_across_recreations() {
        use commonware_runtime::tokio;
        use std::{env, fs};

        let db_path = env::temp_dir().join("persistent_queue_test_unique");

        // Clean up any existing data
        if db_path.exists() {
            fs::remove_dir_all(&db_path).ok();
        }

        // First phase: Create queue, add data, and close
        {
            let cfg = tokio::Config::default().with_storage_directory(db_path.clone());
            let executor = tokio::Runner::new(cfg);

            executor.start(|context| async move {
                let mut queue =
                    create_test_queue_with_context("test_persistence_unique", context).await;

                // Add some test data
                queue.push(100).await;
                queue.push(200).await;
                queue.push(300).await;

                // Verify data is there
                assert_eq!(queue.len().await, 3);
                assert_eq!(queue.peek().await, Some(100));
                assert!(!queue.is_empty().await);

                // Pop one item to change the head pointer
                assert_eq!(queue.pop().await, Some(100));
                assert_eq!(queue.len().await, 2);
            });
        } // Database closes here when executor drops

        // Second phase: Recreate queue with same path and verify data persists
        {
            let cfg = tokio::Config::default().with_storage_directory(db_path.clone());
            let executor = tokio::Runner::new(cfg);

            executor.start(|context| async move {
                let mut queue =
                    create_test_queue_with_context("test_persistence_unique", context).await;

                // Verify persisted data is still there
                assert_eq!(queue.len().await, 2);
                assert!(!queue.is_empty().await);
                assert_eq!(queue.peek().await, Some(200));

                // Pop remaining items to verify queue state
                assert_eq!(queue.pop().await, Some(200));
                assert_eq!(queue.pop().await, Some(300));
                assert!(queue.is_empty().await);
                assert_eq!(queue.len().await, 0);

                // Add new data to verify queue still works
                queue.push(999).await;
                assert_eq!(queue.peek().await, Some(999));
                assert_eq!(queue.len().await, 1);
            });
        }

        // Clean up test data
        if db_path.exists() {
            fs::remove_dir_all(&db_path).ok();
        }
    }
}
