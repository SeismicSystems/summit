use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write, varint::UInt};
use commonware_consensus::types::{Epoch, Height, View};
use commonware_cryptography::{Digest, Digestible, Hasher};

const MOCK_BLOCKS_PER_EPOCH: u64 = 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block<D: Digest> {
    /// The parent block's digest.
    pub parent: D,

    /// The height of the block in the blockchain.
    pub height: Height,

    /// The timestamp of the block (in milliseconds since the Unix epoch).
    pub timestamp: u64,

    /// The epoch associated with this block in syncer tests.
    pub epoch: Epoch,

    /// The view associated with this block in syncer tests.
    pub view: View,

    /// Pre-computed digest of the block.
    digest: D,
}

impl<D: Digest> Block<D> {
    fn compute_digest<H: Hasher<Digest = D>>(parent: &D, height: Height, timestamp: u64) -> D {
        let mut hasher = H::new();
        hasher.update(parent);
        hasher.update(&height.get().to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.finalize()
    }

    pub fn new<H: Hasher<Digest = D>>(parent: D, height: Height, timestamp: u64) -> Self {
        let digest = Self::compute_digest::<H>(&parent, height, timestamp);
        let epoch = Epoch::new(height.get() / MOCK_BLOCKS_PER_EPOCH);
        let view = View::new(height.get());
        Self {
            parent,
            height,
            timestamp,
            epoch,
            view,
            digest,
        }
    }
}

impl<D: Digest> Write for Block<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.parent.write(writer);
        self.height.write(writer);
        UInt(self.timestamp).write(writer);
        self.digest.write(writer);
    }
}

impl<D: Digest> Read for Block<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let parent = D::read(reader)?;
        let height = Height::read(reader)?;
        let timestamp = UInt::read(reader)?.into();
        let epoch = Epoch::new(height.get() / MOCK_BLOCKS_PER_EPOCH);
        let view = View::new(height.get());
        let digest = D::read(reader)?;

        // Pre-compute the digest
        Ok(Self {
            parent,
            height,
            timestamp,
            epoch,
            view,
            digest,
        })
    }
}

impl<D: Digest> EncodeSize for Block<D> {
    fn encode_size(&self) -> usize {
        self.parent.encode_size()
            + self.height.encode_size()
            + UInt(self.timestamp).encode_size()
            + self.digest.encode_size()
    }
}

impl<D: Digest> Digestible for Block<D> {
    type Digest = D;

    fn digest(&self) -> D {
        self.digest
    }
}

impl<D: Digest> commonware_consensus::Heightable for Block<D> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<D: Digest> commonware_consensus::Epochable for Block<D> {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

impl<D: Digest> commonware_consensus::Block for Block<D> {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl<D: Digest> commonware_consensus::Viewable for Block<D> {
    fn view(&self) -> View {
        self.view
    }
}
