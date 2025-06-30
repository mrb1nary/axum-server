use std::net::SocketAddr;

use axum::{Json, Router, routing::post, http::StatusCode};
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

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

impl ErrorResponse {
    fn new(msg: &str) -> (StatusCode, Json<ErrorResponse>) {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { success: false, error: msg.to_string() }))
    }
}

#[derive(Serialize)]
struct KeypairResponse {
    success: bool,
    data: KeypairData,
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
        data: KeypairData { pubkey, secret },
    })
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    mintAuthority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    success: bool,
    data: CreateTokenData,
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

async fn create_token(Json(req): Json<CreateTokenRequest>) -> Result<Json<CreateTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mint_authority = Pubkey::from_str(&req.mintAuthority).map_err(|_| ErrorResponse::new("Invalid mint authority pubkey"))?;
    let mint = Pubkey::from_str(&req.mint).map_err(|_| ErrorResponse::new("Invalid mint pubkey"))?;

    let ix = initialize_mint(&spl_token::id(), &mint, &mint_authority, None, req.decimals)
        .map_err(|_| ErrorResponse::new("Failed to create initialize_mint instruction"))?;

    let accounts = ix.accounts.iter().map(|meta| AccountMetaInfo {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();

    let instruction_data = base64::encode(ix.data);

    Ok(Json(CreateTokenResponse {
        success: true,
        data: CreateTokenData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        },
    }))
}

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
    data: MintInstructionData,
}

#[derive(Serialize)]
struct MintInstructionData {
    program_id: String,
    accounts: Vec<AccountMetaInfo>,
    instruction_data: String,
}

async fn mint_token(Json(req): Json<MintTokenRequest>) -> Result<Json<MintTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mint = Pubkey::from_str(&req.mint).map_err(|_| ErrorResponse::new("Invalid mint pubkey"))?;
    let destination = Pubkey::from_str(&req.destination).map_err(|_| ErrorResponse::new("Invalid destination pubkey"))?;
    let authority = Pubkey::from_str(&req.authority).map_err(|_| ErrorResponse::new("Invalid authority pubkey"))?;

    let ix = mint_to(&spl_token::id(), &mint, &destination, &authority, &[], req.amount)
        .map_err(|_| ErrorResponse::new("Failed to create mint_to instruction"))?;

    let accounts = ix.accounts.iter().map(|meta| AccountMetaInfo {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();

    let instruction_data = base64::encode(ix.data);

    Ok(Json(MintTokenResponse {
        success: true,
        data: MintInstructionData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        },
    }))
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    success: bool,
    data: SignMessageData,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

async fn sign_message_handler(Json(req): Json<SignMessageRequest>) -> Result<Json<SignMessageResponse>, (StatusCode, Json<ErrorResponse>)> {
    if req.message.is_empty() || req.secret.is_empty() {
        return Err(ErrorResponse::new("Missing message or secret"));
    }

    let secret_bytes = bs58::decode(&req.secret).into_vec().map_err(|_| ErrorResponse::new("Invalid secret encoding"))?;
    let keypair = Keypair::from_bytes(&secret_bytes).map_err(|_| ErrorResponse::new("Invalid secret bytes"))?;

    let signature = keypair.sign_message(req.message.as_bytes());
    let signature_base64 = base64::encode(signature.as_ref());
    let public_key = keypair.pubkey().to_string();

    Ok(Json(SignMessageResponse {
        success: true,
        data: SignMessageData {
            signature: signature_base64,
            public_key,
            message: req.message,
        },
    }))
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    success: bool,
    data: VerifyMessageData,
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
}

async fn verify_message_handler(Json(req): Json<VerifyMessageRequest>) -> Result<Json<VerifyMessageResponse>, (StatusCode, Json<ErrorResponse>)> {
    let signature_bytes = base64::decode(&req.signature).map_err(|_| ErrorResponse::new("Invalid base64 signature"))?;
    let signature = Signature::try_from(signature_bytes.as_slice()).map_err(|_| ErrorResponse::new("Invalid signature bytes"))?;
    let pubkey = Pubkey::from_str(&req.pubkey).map_err(|_| ErrorResponse::new("Invalid pubkey"))?;

    let valid = signature.verify(pubkey.as_ref(), req.message.as_bytes());

    Ok(Json(VerifyMessageResponse {
        success: true,
        data: VerifyMessageData {
            valid,
            message: req.message,
            pubkey: req.pubkey,
        },
    }))
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    success: bool,
    data: SendSolData,
}

#[derive(Serialize)]
struct SendSolData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

async fn send_sol_handler(Json(req): Json<SendSolRequest>) -> Result<Json<SendSolResponse>, (StatusCode, Json<ErrorResponse>)> {
    if req.lamports == 0 {
        return Err(ErrorResponse::new("Transfer amount must be greater than 0"));
    }

    let from_pubkey = Pubkey::from_str(&req.from).map_err(|_| ErrorResponse::new("Invalid from pubkey"))?;
    let to_pubkey = Pubkey::from_str(&req.to).map_err(|_| ErrorResponse::new("Invalid to pubkey"))?;

    let ix = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);
    let program_id = ix.program_id.to_string();
    let accounts = ix.accounts.iter().map(|meta| meta.pubkey.to_string()).collect();
    let instruction_data = base64::encode(ix.data);

    Ok(Json(SendSolResponse {
        success: true,
        data: SendSolData {
            program_id,
            accounts,
            instruction_data,
        },
    }))
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenResponse {
    success: bool,
    data: SendTokenData,
}

#[derive(Serialize)]
struct SendTokenData {
    program_id: String,
    accounts: Vec<AccountMetaInfo>,
    instruction_data: String,
}

async fn send_token_handler(Json(req): Json<SendTokenRequest>) -> Result<Json<SendTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let destination = Pubkey::from_str(&req.destination).map_err(|_| ErrorResponse::new("Invalid destination pubkey"))?;
    let mint = Pubkey::from_str(&req.mint).map_err(|_| ErrorResponse::new("Invalid mint pubkey"))?;
    let owner = Pubkey::from_str(&req.owner).map_err(|_| ErrorResponse::new("Invalid owner pubkey"))?;

    let ix = transfer_checked(&spl_token::id(), &owner, &mint, &destination, &owner, &[], req.amount, 0)
        .map_err(|_| ErrorResponse::new("Failed to create transfer_checked instruction"))?;

    let accounts = ix.accounts.iter().map(|meta| AccountMetaInfo {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();

    let instruction_data = base64::encode(ix.data);

    Ok(Json(SendTokenResponse {
        success: true,
        data: SendTokenData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        },
    }))
}

#[tokio::main]
async fn main() {
    let port = 8080;
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