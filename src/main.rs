use std::net::SocketAddr;

use axum::{Json, Router, routing::post};
use serde::{Deserialize, Serialize};
use solana_sdk::bs58;
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;
use tokio::net::TcpListener;
use spl_token::instruction::initialize_mint;

#[derive(Serialize)]
struct KeypairResponse {
    success: bool,
    data: Option<KeypairData>,
    error: Option<String>,
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

async fn generate_keypair() -> Json<KeypairResponse> {
    
    let keypair = Keypair::new();

    
    let pubkey = keypair.pubkey().to_string();

    
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    
    Json(KeypairResponse {
        success: true,
        data: Some(KeypairData { pubkey, secret }),
        error: None,
    })
}


//-----------------------------------------------------------------//

#[derive(Deserialize)]
struct CreateTokenRequest {
    mintAuthority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    success: bool,
    data: Option<String>,
    error: Option<String>,
}

async fn create_token(Json(req): Json<CreateTokenRequest>) -> Json<CreateTokenResponse> {
    
    let mint_authority = match Pubkey::from_str(&req.mintAuthority) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(CreateTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid mintAuthority pubkey".to_string()),
            });
        }
    };
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(CreateTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid mint pubkey".to_string()),
            });
        }
    };

    
    let ix: Instruction = match initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        req.decimals,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return Json(CreateTokenResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create instruction: {e}")),
            });
        }
    };

    
    let data = base64::encode(ix.data);

    Json(CreateTokenResponse {
        success: true,
        data: Some(data),
        error: None,
    })
}

//------------------------------------------------------//


#[tokio::main]
async fn main() {
    
    let port = 8080;

    let addr = SocketAddr::from(([0, 0, 0, 0], port)); 

    let app = Router::new()
    .route("/keypair", post(generate_keypair))
    .route("/token/create", post(create_token));

    let tcp = TcpListener::bind(addr).await.unwrap();
    println!("Server running on {}", addr);
    axum::serve(tcp, app).await.unwrap();
}






