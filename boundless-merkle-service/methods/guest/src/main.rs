use risc0_zkvm::guest::env;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct MerkleProof {
    leaf_value: String,
    proof_path: Vec<(String, bool)>, // (hash, is_right)
}

struct MerkleTree {
    leaves: Vec<String>,
    nodes: Vec<Vec<String>>,
    data_values: Vec<String>,  // Store original data values
}

impl MerkleTree {
    fn new() -> Self {
        MerkleTree {
            leaves: Vec::new(),
            nodes: Vec::new(),
            data_values: Vec::new(),
        }
    }

    fn hash(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn insert(&mut self, data: String) {
        let leaf_hash = Self::hash(&data);
        self.leaves.push(leaf_hash.clone());
        self.data_values.push(data);
        
        // Rebuild the tree after inserting new leaf
        self.nodes.clear();
        let mut current_level = self.leaves.clone();
        
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    let combined = format!("{}{}", chunk[0], chunk[1]);
                    let parent_hash = Self::hash(&combined);
                    next_level.push(parent_hash);
                } else {
                    next_level.push(chunk[0].clone());
                }
            }
            
            // Only push internal nodes to self.nodes, not the leaves
            if next_level.len() > 0 {  // Only add non-leaf levels
                self.nodes.push(next_level.clone());
            }
            current_level = next_level;
        }
    }

    fn generate_proof(&self, leaf_value: &str) -> Option<MerkleProof> {
        let leaf_hash = Self::hash(leaf_value);
        let mut leaf_index = self.leaves.iter().position(|x| x == &leaf_hash)?;
        let mut proof_path = Vec::new();
        
        // Start with leaf level
        let mut current_level = &self.leaves;
        
        // Traverse up through all internal node levels
        for level in &self.nodes {
            let sibling_idx = if leaf_index % 2 == 0 {
                leaf_index + 1
            } else {
                leaf_index - 1
            };
            
            // Only add to proof path if sibling exists
            if sibling_idx < current_level.len() {
                proof_path.push((current_level[sibling_idx].clone(), leaf_index % 2 == 0));
            }
            
            // Update index for next level up
            leaf_index /= 2;
            current_level = level;
        }
    
        Some(MerkleProof {
            leaf_value: leaf_value.to_string(),
            proof_path,
        })
    }

    fn verify_proof(&self, proof: &MerkleProof) -> bool {
        let mut current_hash = Self::hash(&proof.leaf_value);

        for (sibling_hash, is_right) in &proof.proof_path {
            let combined = if *is_right {
                format!("{}{}", current_hash, sibling_hash)
            } else {
                format!("{}{}", sibling_hash, current_hash)
            };
            current_hash = Self::hash(&combined);
        }

        Some(current_hash) == self.get_root()
    }

    fn get_root(&self) -> Option<String> {
        self.nodes.last()
            .and_then(|level| level.first())
            .cloned()
            .or_else(|| self.leaves.first().cloned())
    }
}

#[derive(Deserialize)]
struct Input {
    operation: String,
    data: Vec<String>,
    proof_request: Option<String>,
    proof: Option<MerkleProof>,
}

#[derive(Serialize)]
struct Output {
    root: Option<String>,
    proof: Option<MerkleProof>,
    verified: Option<bool>,
    receipt: Option<String>,
    request_id: Option<u64>,
    seal: Option<String>
}

fn main() {
    let input: Input = env::read();
    let mut tree = MerkleTree::new();
    
    let output = match input.operation.as_str() {
        "prove" => {
            for item in input.data {
                tree.insert(item);
            }
            let proof = input.proof_request.and_then(|value| tree.generate_proof(&value));
            Output {
                root: tree.get_root(),
                proof,
                verified: None,
                receipt: None,
                request_id: None,
                seal: None,
            }
        },
        "verify" => {
            for item in input.data {
                tree.insert(item);
            }
            let verified = input.proof.map(|proof| tree.verify_proof(&proof));
            Output {
                root: tree.get_root(),
                proof: None,
                verified,
                receipt: None,
                request_id: None,
                seal: None,
            }
        },
        _ => Output {
            root: None,
            proof: None,
            verified: None,
            receipt: None,
            request_id: None,
            seal: None,
        },
    };
    
    env::commit(&output);
}