use actix_web::{web, App, HttpServer, HttpResponse};
use methods::{GUEST_ELF, GUEST_ID};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use anyhow::{Context, Result};
use url::Url;
use boundless_market::{
    client::ClientBuilder,
    contracts::{Input, Offer, Predicate, ProofRequestBuilder, Requirements},
    input::InputBuilder,
    storage::StorageProviderConfig,
};
use alloy::{
    primitives::{utils::parse_ether, Address},
    signers::local::PrivateKeySigner,
};
use dotenv::dotenv;

/// Timeout for waiting for a transaction to be confirmed
const TX_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct ProcessError(String);

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ProcessError {}

impl From<anyhow::Error> for ProcessError {
    fn from(err: anyhow::Error) -> Self {
        ProcessError(err.to_string())
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Request {
    operation: String,
    data: Vec<String>,
    proof_request: Option<String>,
    proof: Option<MerkleProof>,
}

#[derive(Serialize, Deserialize, Clone)]
struct MerkleProof {
    leaf_value: String,
    proof_path: Vec<(String, bool)>,
}

#[derive(Serialize, Deserialize)]
struct Response {
    root: Option<String>,
    proof: Option<MerkleProof>,
    verified: Option<bool>,
    receipt: Option<String>,
    // New fields for Boundless integration
    request_id: Option<u64>,
    seal: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct BoundlessConfig {
    rpc_url: String,
    wallet_private_key: String,
    boundless_market_address: String,
    set_verifier_address: String,
    order_stream_url: Option<String>,
    use_offchain: bool,
}

fn load_boundless_config() -> Result<BoundlessConfig, ProcessError> {
    Ok(BoundlessConfig {
        rpc_url: std::env::var("RPC_URL")
            .map_err(|_| ProcessError("RPC_URL environment variable not set".to_string()))?,
        wallet_private_key: std::env::var("PRIVATE_KEY")
            .map_err(|_| ProcessError("PRIVATE_KEY environment variable not set".to_string()))?,
        boundless_market_address: std::env::var("BOUNDLESS_MARKET_ADDRESS")
            .map_err(|_| ProcessError("BOUNDLESS_MARKET_ADDRESS environment variable not set".to_string()))?,
        set_verifier_address: std::env::var("SET_VERIFIER_ADDRESS")
            .map_err(|_| ProcessError("SET_VERIFIER_ADDRESS environment variable not set".to_string()))?,
        order_stream_url: std::env::var("ORDER_STREAM_URL").ok(),
        use_offchain: std::env::var("USE_OFFCHAIN").map(|v| v == "true").unwrap_or(false),
    })
}

async fn create_boundless_client(config: &BoundlessConfig) -> Result<boundless_market::client::Client, ProcessError> {
    let rpc_url = Url::parse(&config.rpc_url)
        .map_err(|e| ProcessError(format!("Invalid RPC URL: {}", e)))?;
    
    let wallet_signer = PrivateKeySigner::from_hex(&config.wallet_private_key)
        .map_err(|e| ProcessError(format!("Invalid private key: {}", e)))?;
    
    let boundless_market_address = config.boundless_market_address.parse::<Address>()
        .map_err(|e| ProcessError(format!("Invalid Boundless market address: {}", e)))?;
    
    let set_verifier_address = config.set_verifier_address.parse::<Address>()
        .map_err(|e| ProcessError(format!("Invalid set verifier address: {}", e)))?;
    
    let order_stream_url = if let Some(url) = &config.order_stream_url {
        Some(Url::parse(url).map_err(|e| ProcessError(format!("Invalid order stream URL: {}", e)))?)
    } else {
        None
    };
    
    let client = ClientBuilder::default()
        .with_rpc_url(rpc_url)
        .with_boundless_market_address(boundless_market_address)
        .with_set_verifier_address(set_verifier_address)
        .with_order_stream_url(config.use_offchain.then_some(order_stream_url).flatten())
        .with_storage_provider_config(Some(StorageProviderConfig::default()))
        .with_private_key(wallet_signer)
        .build()
        .await
        .map_err(|e| ProcessError(format!("Failed to create Boundless client: {}", e)))?;
    
    Ok(client)
}

async fn request_boundless_proof(request: Request) -> Result<Response, ProcessError> {
    println!("Requesting proof from Boundless market...");
    let config = load_boundless_config()?;
    let boundless_client = create_boundless_client(&config).await?;
    
    // Upload the ELF to storage
    let image_url = boundless_client.upload_image(GUEST_ELF)
        .await
        .map_err(|e| ProcessError(format!("Failed to upload image: {}", e)))?;
    println!("Uploaded image to {}", image_url);
    
    // Serialize the input data
    let input_bytes = serde_json::to_vec(&request)
        .map_err(|e| ProcessError(format!("Failed to serialize input: {}", e)))?;
    
    let input_builder = InputBuilder::new().write_slice(&input_bytes);
    let guest_env = input_builder.clone().build_env()
        .map_err(|e| ProcessError(format!("Failed to build environment: {}", e)))?;
    let guest_env_bytes = guest_env.encode()
        .map_err(|e| ProcessError(format!("Failed to encode environment: {}", e)))?;
    
    // Dry run to get journal and cycle count
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(&request)
        .map_err(|e| ProcessError(format!("Failed to build executor env: {}", e)))?
        .build()
        .map_err(|e| ProcessError(format!("Failed to build executor env: {}", e)))?;
    
    println!("Running dry execution to estimate cycles...");
    let session_info = risc0_zkvm::default_executor()
        .execute(env.try_into().unwrap(), GUEST_ELF)
        .map_err(|e| ProcessError(format!("Failed to execute guest: {}", e)))?;
    
    let mcycles_count = session_info
        .segments
        .iter()
        .map(|segment| 1 << segment.po2)
        .sum::<u64>()
        .div_ceil(1_000_000);
    
    let journal = session_info.journal;
    println!("Estimated cycles: {} MCycles", mcycles_count);
    
    // Create input for the request
    let request_input = if guest_env_bytes.len() > 2 << 10 {
        let input_url = boundless_client.upload_input(&guest_env_bytes)
            .await
            .map_err(|e| ProcessError(format!("Failed to upload input: {}", e)))?;
        println!("Uploaded input to {}", input_url);
        Input::url(input_url)
    } else {
        println!("Sending input inline with request");
        Input::inline(guest_env_bytes)
    };
    
    // Create proof request
    let request = ProofRequestBuilder::new()
        .with_image_url(image_url.to_string())
        .with_input(request_input)
        .with_requirements(Requirements::new(
            GUEST_ID,
            Predicate::digest_match(journal.digest()),
        ))
        .with_offer(
            Offer::default()
                .with_min_price_per_mcycle(parse_ether("0.001").unwrap(), mcycles_count)
                .with_max_price_per_mcycle(parse_ether("0.002").unwrap(), mcycles_count)
                .with_timeout(1000),
        )
        .build()
        .map_err(|e| ProcessError(format!("Failed to build proof request: {}", e)))?;
    
    // Submit request
    println!("Submitting request to Boundless market...");
    let (request_id, expires_at) = if config.use_offchain {
        boundless_client.submit_request_offchain(&request)
            .await
            .map_err(|e| ProcessError(format!("Failed to submit offchain request: {}", e)))?
    } else {
        boundless_client.submit_request(&request)
            .await
            .map_err(|e| ProcessError(format!("Failed to submit request: {}", e)))?
    };
    
    println!("Request 0x{:x} submitted, waiting for fulfillment", request_id);
    
    // Wait for the request to be fulfilled
    let (returned_journal, seal) = boundless_client
        .wait_for_request_fulfillment(request_id, Duration::from_secs(5), expires_at)
        .await
        .map_err(|e| ProcessError(format!("Failed waiting for request fulfillment: {}", e)))?;
    
    println!("Request 0x{:x} fulfilled", request_id);
    
    // Decode the journal
    let output: Response = returned_journal.decode()
        .unwrap_or_else(|_| Response {
            root: None,
            proof: None,
            verified: Some(true),
            receipt: None,
            request_id: Some(request_id),
            seal: None,
        });
    
    // Enhance the response with Boundless data
    let mut enhanced_output = output;
    enhanced_output.request_id = Some(request_id);
    enhanced_output.seal = Some(hex::encode(&seal));
    enhanced_output.verified = Some(true);
    
    Ok(enhanced_output)
}

async fn process(req: web::Json<Request>) -> HttpResponse {
    let request_data = req.0.clone();
    
    println!("Starting request processing...");
    println!("Operation: {}", request_data.operation);
    println!("Input data: {:?}", request_data.data);
    
    match request_boundless_proof(request_data).await {
        Ok(output) => HttpResponse::Ok().json(output),
        Err(e) => {
            println!("Processing error: {}", e);
            HttpResponse::InternalServerError().json(format!("Processing error: {}", e))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    println!("Starting Boundless integration server on port 3001...");
    
    HttpServer::new(|| {
        App::new()
            .route("/process", web::post().to(process))
    })
    .bind("127.0.0.1:3001")?
    .run()
    .await
}