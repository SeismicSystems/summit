use commonware_cryptography::bls12381::primitives::{group, poly::Poly};
use summit_types::{Identity, PublicKey};

#[derive(Clone)]
pub struct ApplicationConfig {
    /// Participants active in consensus.
    pub participants: Vec<PublicKey>,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,

    /// Url to the engine api on Seismic Reth
    pub engine_url: String,

    /// Shared jwt auth key for Seismic Reth engine api
    pub engine_jwt: String,

    pub partition_prefix: String,

    pub genesis_hash: [u8; 32],

    pub polynomial: Poly<Identity>,

    pub share: group::Share,
}

#[cfg(test)]
mod tests {
    use commonware_cryptography::bls12381::dkg::ops;
    use commonware_cryptography::bls12381::primitives::variant::MinPk;
    use rand::rngs::OsRng;

    use crate::ApplicationConfig;
    
    fn create_test_config() -> ApplicationConfig {
        
        // Generate test DKG values
        let (polynomial, shares) = ops::generate_shares::<_, MinPk>(&mut OsRng, None, 1, 1);
        
        // Create a basic config for testing
        ApplicationConfig {
            participants: vec![], // Empty for basic testing, would be filled in real usage
            mailbox_size: 100,
            engine_url: "http://localhost:8551".to_string(),
            engine_jwt: "0x1234567890abcdef".to_string(),
            partition_prefix: "test".to_string(),
            genesis_hash: [0u8; 32],
            polynomial,
            share: shares[0].clone(),
        }
    }

    /// Test that Clone preserves all field values correctly.
    #[test]
    fn test_config_clone_preserves_data() {
        let config = create_test_config();
        let cloned = config.clone();
        
        assert_eq!(config.participants.len(), cloned.participants.len());
        assert_eq!(config.mailbox_size, cloned.mailbox_size);
        assert_eq!(config.engine_url, cloned.engine_url);
        assert_eq!(config.partition_prefix, cloned.partition_prefix);
        assert_eq!(config.genesis_hash, cloned.genesis_hash);
    }
}
