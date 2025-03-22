use clap::{Parser, Subcommand};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Insert {
        /// Data items to insert (multiple values allowed)
        #[arg(required = true)]
        data: Vec<String>,
    },
    Prove {
        /// Data items to build the tree
        #[arg(required = true)]
        data: Vec<String>,
        /// Value to generate proof for
        #[arg(required = true)]
        value: String,
    },
    Verify {
        /// Data items in the tree
        #[arg(required = true)]
        data: Vec<String>,
        /// Value to verify
        #[arg(required = true)]
        value: String,
        /// Proof path (comma-separated pairs of hash:side, where side is 'left' or 'right')
        #[arg(required = true)]
        proof: String,
    },
}

#[derive(Serialize, Deserialize)]
struct Request {
    operation: String,
    data: Vec<String>,
    proof_request: Option<String>,
    proof: Option<MerkleProof>,
}

#[derive(Serialize, Deserialize, Debug)]
struct MerkleProof {
    leaf_value: String,
    proof_path: Vec<(String, bool)>,
}

#[derive(Deserialize, Debug)]
struct Response {
    root: Option<String>,
    proof: Option<MerkleProof>,
    verified: Option<bool>,
}

async fn send_request(request: Request) -> Result<Response, Box<dyn Error>> {
    let client = Client::new();
    let response = client
        .post("http://localhost:8080/process")
        .json(&request)
        .send()
        .await?
        .json::<Response>()
        .await?;
    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Insert { data } => {
            let request = Request {
                operation: "insert".to_string(),
                data,
                proof_request: None,
                proof: None,
            };

            let response = send_request(request).await?;
            println!("Root hash: {}", response.root.unwrap_or_default());
        }
        Commands::Prove { data, value } => {
            let request = Request {
                operation: "prove".to_string(),
                data,
                proof_request: Some(value),
                proof: None,
            };

            let response = send_request(request).await?;
            if let Some(proof) = response.proof {
                println!("Merkle Proof:");
                println!("Leaf value: {}", proof.leaf_value);
                println!("Proof path:");
                for (hash, is_right) in proof.proof_path {
                    println!("  Hash: {}, Side: {}", hash, if is_right { "right" } else { "left" });
                }
                println!("Root hash: {}", response.root.unwrap_or_default());
            } else {
                println!("No proof generated");
            }
        }
        Commands::Verify { data, value, proof } => {
            // Parse proof string
            let proof_pairs: Vec<&str> = proof.split(',').collect();
            let mut proof_path = Vec::new();
            
            for pair in proof_pairs {
                let parts: Vec<&str> = pair.split(':').collect();
                if parts.len() == 2 {
                    proof_path.push((
                        parts[0].to_string(),
                        parts[1] == "right",
                    ));
                }
            }

            let request = Request {
                operation: "verify".to_string(),
                data,
                proof_request: None,
                proof: Some(MerkleProof {
                    leaf_value: value,
                    proof_path,
                }),
            };

            let response = send_request(request).await?;
            println!("Verification result: {}", response.verified.unwrap_or(false));
        }
    }

    Ok(())
}