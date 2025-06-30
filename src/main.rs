use std::net::SocketAddr;

use axum::{Json, Router, routing::post, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;
use solana_sdk::system_instruction;
use solana_sdk::{bs58, signature::Signature};
use spl_token::instruction::{initialize_mint, mint_to, transfer_checked};
use std::str::FromStr;
use tokio::net::TcpListener;

// 1. Generate keypair
#[derive(Serialize)]
struct KeypairResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<KeypairData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

async fn generate_keypair() -> impl IntoResponse {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    (StatusCode::OK, Json(KeypairResponse {
        success: true,
        data: Some(KeypairData { pubkey, secret }),
        error: None,
    }))
}

// 2. Create Token
#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<CreateTokenData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct CreateTokenData {
    program_id: String,
    accounts: Vec<AccountMetaInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountMetaInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

async fn create_token(Json(req): Json<CreateTokenRequest>) -> impl IntoResponse {
    // Validate required fields
    if req.mint_authority.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(CreateTokenResponse {
            success: false,
            data: None,
            error: Some("mintAuthority is required and cannot be empty".to_string()),
        }));
    }
    if req.mint.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(CreateTokenResponse {
            success: false,
            data: None,
            error: Some("mint is required and cannot be empty".to_string()),
        }));
    }
    if req.decimals > 9 {
        return (StatusCode::BAD_REQUEST, Json(CreateTokenResponse {
            success: false,
            data: None,
            error: Some("decimals must be between 0 and 9".to_string()),
        }));
    }

    // Validate pubkey formats
    let mint_authority = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(CreateTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid mintAuthority format".to_string()),
            }));
        }
    };
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(CreateTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid mint format".to_string()),
            }));
        }
    };

    // Check if mint and authority are the same (edge case)
    if mint_authority == mint {
        return (StatusCode::BAD_REQUEST, Json(CreateTokenResponse {
            success: false,
            data: None,
            error: Some("mintAuthority and mint cannot be the same".to_string()),
        }));
    }

    let ix: Instruction = match initialize_mint(&spl_token::id(), &mint, &mint_authority, None, req.decimals) {
        Ok(ix) => ix,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(CreateTokenResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create instruction: {}", e)),
            }));
        }
    };

    let accounts = ix.accounts.iter().map(|meta| AccountMetaInfo {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();

    let instruction_data = base64::encode(ix.data);

    (StatusCode::OK, Json(CreateTokenResponse {
        success: true,
        data: Some(CreateTokenData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        }),
        error: None,
    }))
}

// 3. Mint Token
#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Serialize)]
struct MintTokenResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<MintInstructionData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct MintInstructionData {
    program_id: String,
    accounts: Vec<AccountMetaInfo>,
    instruction_data: String,
}

async fn mint_token(Json(req): Json<MintTokenRequest>) -> impl IntoResponse {
    // Validate required fields
    if req.mint.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(MintTokenResponse {
            success: false,
            data: None,
            error: Some("mint is required and cannot be empty".to_string()),
        }));
    }
    if req.destination.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(MintTokenResponse {
            success: false,
            data: None,
            error: Some("destination is required and cannot be empty".to_string()),
        }));
    }
    if req.authority.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(MintTokenResponse {
            success: false,
            data: None,
            error: Some("authority is required and cannot be empty".to_string()),
        }));
    }
    if req.amount == 0 {
        return (StatusCode::BAD_REQUEST, Json(MintTokenResponse {
            success: false,
            data: None,
            error: Some("amount must be greater than 0".to_string()),
        }));
    }
    if req.amount > u64::MAX / 2 {
        return (StatusCode::BAD_REQUEST, Json(MintTokenResponse {
            success: false,
            data: None,
            error: Some("amount is too large".to_string()),
        }));
    }

    // Validate pubkey formats
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(MintTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid mint format".to_string()),
            }));
        }
    };
    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(MintTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid destination format".to_string()),
            }));
        }
    };
    let authority = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(MintTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid authority format".to_string()),
            }));
        }
    };

    // Check if mint and destination are the same (edge case)
    if mint == destination {
        return (StatusCode::BAD_REQUEST, Json(MintTokenResponse {
            success: false,
            data: None,
            error: Some("mint and destination cannot be the same".to_string()),
        }));
    }

    let ix = match mint_to(&spl_token::id(), &mint, &destination, &authority, &[], req.amount) {
        Ok(ix) => ix,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(MintTokenResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create mint instruction: {}", e)),
            }));
        }
    };

    let accounts = ix.accounts.iter().map(|meta| AccountMetaInfo {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();

    let instruction_data = base64::encode(ix.data);

    (StatusCode::OK, Json(MintTokenResponse {
        success: true,
        data: Some(MintInstructionData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        }),
        error: None,
    }))
}

// 4. Sign Message
#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<SignMessageData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

async fn sign_message_handler(Json(req): Json<SignMessageRequest>) -> impl IntoResponse {
    // Validate required fields
    if req.message.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(SignMessageResponse {
            success: false,
            data: None,
            error: Some("message is required and cannot be empty".to_string()),
        }));
    }
    if req.secret.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(SignMessageResponse {
            success: false,
            data: None,
            error: Some("secret is required and cannot be empty".to_string()),
        }));
    }
    if req.message.len() > 1024 {
        return (StatusCode::BAD_REQUEST, Json(SignMessageResponse {
            success: false,
            data: None,
            error: Some("message is too long (max 1024 characters)".to_string()),
        }));
    }

    // Validate secret key format
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(SignMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid secret key format".to_string()),
            }));
        }
    };

    // Check secret key length
    if secret_bytes.len() != 64 {
        return (StatusCode::BAD_REQUEST, Json(SignMessageResponse {
            success: false,
            data: None,
            error: Some("Invalid secret key length".to_string()),
        }));
    }

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(SignMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid secret key bytes".to_string()),
            }));
        }
    };

    let signature = keypair.sign_message(req.message.as_bytes());
    let signature_base64 = base64::encode(signature.as_ref());
    let public_key = keypair.pubkey().to_string();

    (StatusCode::OK, Json(SignMessageResponse {
        success: true,
        data: Some(SignMessageData {
            signature: signature_base64,
            public_key,
            message: req.message,
        }),
        error: None,
    }))
}

// 5. Verify Message
#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<VerifyMessageData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
}

async fn verify_message_handler(Json(req): Json<VerifyMessageRequest>) -> impl IntoResponse {
    // Validate required fields
    if req.message.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(VerifyMessageResponse {
            success: false,
            data: None,
            error: Some("message is required and cannot be empty".to_string()),
        }));
    }
    if req.signature.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(VerifyMessageResponse {
            success: false,
            data: None,
            error: Some("signature is required and cannot be empty".to_string()),
        }));
    }
    if req.pubkey.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(VerifyMessageResponse {
            success: false,
            data: None,
            error: Some("pubkey is required and cannot be empty".to_string()),
        }));
    }
    if req.message.len() > 1024 {
        return (StatusCode::BAD_REQUEST, Json(VerifyMessageResponse {
            success: false,
            data: None,
            error: Some("message is too long (max 1024 characters)".to_string()),
        }));
    }

    // Validate signature format
    let signature_bytes = match base64::decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(VerifyMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid base64 signature format".to_string()),
            }));
        }
    };

    // Check signature length
    if signature_bytes.len() != 64 {
        return (StatusCode::BAD_REQUEST, Json(VerifyMessageResponse {
            success: false,
            data: None,
            error: Some("Invalid signature length".to_string()),
        }));
    }

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(VerifyMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid signature bytes".to_string()),
            }));
        }
    };

    let pubkey = match Pubkey::from_str(&req.pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(VerifyMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid pubkey format".to_string()),
            }));
        }
    };

    let valid = signature.verify(pubkey.as_ref(), req.message.as_bytes());

    (StatusCode::OK, Json(VerifyMessageResponse {
        success: true,
        data: Some(VerifyMessageData {
            valid,
            message: req.message,
            pubkey: req.pubkey,
        }),
        error: None,
    }))
}

// 6. Send SOL
#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<SendSolData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct SendSolData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

async fn send_sol_handler(Json(req): Json<SendSolRequest>) -> impl IntoResponse {
    // Validate required fields
    if req.from.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(SendSolResponse {
            success: false,
            data: None,
            error: Some("from is required and cannot be empty".to_string()),
        }));
    }
    if req.to.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(SendSolResponse {
            success: false,
            data: None,
            error: Some("to is required and cannot be empty".to_string()),
        }));
    }
    if req.lamports == 0 {
        return (StatusCode::BAD_REQUEST, Json(SendSolResponse {
            success: false,
            data: None,
            error: Some("lamports must be greater than 0".to_string()),
        }));
    }
    if req.lamports < 5000 {
        return (StatusCode::BAD_REQUEST, Json(SendSolResponse {
            success: false,
            data: None,
            error: Some("lamports must be at least 5000 (minimum rent exemption)".to_string()),
        }));
    }

    // Validate pubkey formats
    let from_pubkey = match Pubkey::from_str(&req.from) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(SendSolResponse {
                success: false,
                data: None,
                error: Some("Invalid from address format".to_string()),
            }));
        }
    };
    let to_pubkey = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(SendSolResponse {
                success: false,
                data: None,
                error: Some("Invalid to address format".to_string()),
            }));
        }
    };

    // Check if from and to are the same
    if from_pubkey == to_pubkey {
        return (StatusCode::BAD_REQUEST, Json(SendSolResponse {
            success: false,
            data: None,
            error: Some("from and to addresses cannot be the same".to_string()),
        }));
    }

    let ix = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);

    let program_id = ix.program_id.to_string();
    let accounts = ix.accounts.iter().map(|meta| meta.pubkey.to_string()).collect();
    let instruction_data = base64::encode(ix.data);

    (StatusCode::OK, Json(SendSolResponse {
        success: true,
        data: Some(SendSolData {
            program_id,
            accounts,
            instruction_data,
        }),
        error: None,
    }))
}

// 7. Send Token
#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenData {
    program_id: String,
    accounts: Vec<AccountMetaInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SendTokenResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<SendTokenData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn send_token_handler(Json(req): Json<SendTokenRequest>) -> impl IntoResponse {
    // Validate required fields
    if req.destination.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(SendTokenResponse {
            success: false,
            data: None,
            error: Some("destination is required and cannot be empty".to_string()),
        }));
    }
    if req.mint.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(SendTokenResponse {
            success: false,
            data: None,
            error: Some("mint is required and cannot be empty".to_string()),
        }));
    }
    if req.owner.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(SendTokenResponse {
            success: false,
            data: None,
            error: Some("owner is required and cannot be empty".to_string()),
        }));
    }
    if req.amount == 0 {
        return (StatusCode::BAD_REQUEST, Json(SendTokenResponse {
            success: false,
            data: None,
            error: Some("amount must be greater than 0".to_string()),
        }));
    }
    if req.amount > u64::MAX / 2 {
        return (StatusCode::BAD_REQUEST, Json(SendTokenResponse {
            success: false,
            data: None,
            error: Some("amount is too large".to_string()),
        }));
    }

    // Validate pubkey formats
    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(SendTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid destination format".to_string()),
            }));
        }
    };
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(SendTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid mint format".to_string()),
            }));
        }
    };
    let owner = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(SendTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid owner format".to_string()),
            }));
        }
    };

    // Check if destination and owner are the same
    if destination == owner {
        return (StatusCode::BAD_REQUEST, Json(SendTokenResponse {
            success: false,
            data: None,
            error: Some("destination and owner cannot be the same".to_string()),
        }));
    }

    let ix = match transfer_checked(&spl_token::id(), &owner, &mint, &destination, &owner, &[], req.amount, 0) {
        Ok(ix) => ix,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(SendTokenResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create transfer instruction: {}", e)),
            }));
        }
    };

    let accounts = ix.accounts.iter().map(|meta| AccountMetaInfo {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();

    let instruction_data = base64::encode(ix.data);

    (StatusCode::OK, Json(SendTokenResponse {
        success: true,
        data: Some(SendTokenData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        }),
        error: None,
    }))
}

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message_handler))
        .route("/message/verify", post(verify_message_handler))
        .route("/send/sol", post(send_sol_handler))
        .route("/send/token", post(send_token_handler));

    let tcp = TcpListener::bind(addr).await.unwrap();
    println!("Server running on {}", addr);
    axum::serve(tcp, app).await.unwrap();
}
