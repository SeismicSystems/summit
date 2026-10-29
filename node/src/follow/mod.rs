//! Follow mode: following the chain from remote sources, without P2P or Simplex.
//!
//! A follower runs the finalizer and syncer, so it executes every finalized
//! block and tracks validator-set changes, but it takes blocks over
//! request/response from sources it doesn't trust instead of over P2P. Every
//! reply goes through the syncer's own checks against the epoch's validator
//! set, exactly as a P2P peer's reply does.
//!
//! This module holds what only a follower needs: the [`Driver`], the
//! [`FollowSource`]s it fetches from, and the null network for actors that run
//! without P2P. [`crate::engine::Engine::start_follow`] wires them in; see
//! `docs/follow-mode.md` for the whole picture.

mod driver;
pub use driver::{DEFAULT_WINDOW, Driver};
pub(crate) mod null;
pub use null::NullOracle;
mod source;
pub use source::{FollowSource, RpcSource};
