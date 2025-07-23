use crate::{Block, Finalized, Notarized};
use commonware_codec::DecodeExt;
use commonware_consensus::simplex::types::{View, Viewable as _};
use commonware_cryptography::Digestible;
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
pub struct SeedJs {
    pub view: u64,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
pub struct ProofJs {
    pub view: u64,
    pub parent: u64,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
pub struct BlockJs {
    pub parent: Vec<u8>,
    pub height: u64,
    pub timestamp: u64,
    pub digest: Vec<u8>,
}

#[derive(Serialize)]
pub struct NotarizedJs {
    pub proof: ProofJs,
    pub block: BlockJs,
}

#[derive(Serialize)]
pub struct FinalizedJs {
    pub proof: ProofJs,
    pub block: BlockJs,
}

#[wasm_bindgen]
pub fn parse_notarized(_identity: Vec<u8>, bytes: Vec<u8>) -> JsValue {
    // let identity = Identity::decode(identity.as_ref()).expect("invalid identity");
    let Ok(notarized) = Notarized::decode(bytes.as_ref()) else {
        return JsValue::NULL;
    };

    let notarized_js = NotarizedJs {
        proof: ProofJs {
            view: notarized.proof.view(),
            parent: notarized.proof.proposal.parent,
            payload: notarized.proof.proposal.payload.to_vec(),
            signature: Vec::new(),
        },
        block: BlockJs {
            parent: notarized.block.parent.to_vec(),
            height: notarized.block.height,
            timestamp: notarized.block.timestamp,
            digest: notarized.block.digest().to_vec(),
        },
    };
    serde_wasm_bindgen::to_value(&notarized_js).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen]
pub fn parse_seed(_identity: Vec<u8>, bytes: Vec<u8>) -> JsValue {
    // let identity = Identity::decode(identity.as_ref()).expect("invalid identity");
    let Ok(view) = View::decode(bytes.as_ref()) else {
        return JsValue::NULL;
    };

    let seed_js = SeedJs {
        view,
        signature: Vec::new(),
    };
    serde_wasm_bindgen::to_value(&seed_js).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen]
pub fn parse_finalized(_identity: Vec<u8>, bytes: Vec<u8>) -> JsValue {
    //  let identity = Identity::decode(identity.as_ref()).expect("invalid identity");
    let Ok(finalized) = Finalized::decode(bytes.as_ref()) else {
        return JsValue::NULL;
    };

    let finalized_js = FinalizedJs {
        proof: ProofJs {
            view: finalized.proof.view(),
            parent: finalized.proof.proposal.parent,
            payload: finalized.proof.proposal.payload.to_vec(),
            signature: Vec::new(),
        },
        block: BlockJs {
            parent: finalized.block.parent.to_vec(),
            height: finalized.block.height,
            timestamp: finalized.block.timestamp,
            digest: finalized.block.digest().to_vec(),
        },
    };
    serde_wasm_bindgen::to_value(&finalized_js).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen]
pub fn parse_block(bytes: Vec<u8>) -> JsValue {
    let Ok(block) = Block::decode(bytes.as_ref()) else {
        return JsValue::NULL;
    };
    let block_js = BlockJs {
        parent: block.parent.to_vec(),
        height: block.height,
        timestamp: block.timestamp,
        digest: block.digest().to_vec(),
    };
    serde_wasm_bindgen::to_value(&block_js).unwrap_or(JsValue::NULL)
}
