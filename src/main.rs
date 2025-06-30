use std::net::SocketAddr;

use axum::{Json, Router, routing::post};
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

//1. Generate keypair
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

//2. Create Token-----------------------------------------------------------------//

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

    let ix: Instruction =
        match initialize_mint(&spl_token::id(), &mint, &mint_authority, None, req.decimals) {
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

//3. Mint Token------------------------------------------------------//

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
    data: Option<MintInstructionData>,
    error: Option<String>,
}

#[derive(Serialize)]
struct MintInstructionData {
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

async fn mint_token(Json(req): Json<MintTokenRequest>) -> Json<MintTokenResponse> {
    // Parse all the pubkeys
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(MintTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid mint pubkey".to_string()),
            });
        }
    };
    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(MintTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid destination pubkey".to_string()),
            });
        }
    };
    let authority = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(MintTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid authority pubkey".to_string()),
            });
        }
    };

    // Build the instruction
    let ix = match mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return Json(MintTokenResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create mint_to instruction: {e}")),
            });
        }
    };

    // Prepare the account meta info for response
    let accounts = ix
        .accounts
        .iter()
        .map(|meta| AccountMetaInfo {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect();

    // Encode instruction data as base64
    let instruction_data = base64::encode(ix.data);

    Json(MintTokenResponse {
        success: true,
        data: Some(MintInstructionData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        }),
        error: None,
    })
}

//4. Sign message---------------------------------------------------------------//

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    success: bool,
    data: Option<SignMessageData>,
    error: Option<String>,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

async fn sign_message_handler(Json(req): Json<SignMessageRequest>) -> Json<SignMessageResponse> {
    // Check for missing fields
    if req.message.is_empty() || req.secret.is_empty() {
        return Json(SignMessageResponse {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }

    // Decode secret key from base58
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(SignMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid secret key format".to_string()),
            });
        }
    };

    // Create keypair from secret bytes
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return Json(SignMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid secret key bytes".to_string()),
            });
        }
    };

    // Sign the message
    let signature = keypair.sign_message(req.message.as_bytes());

    // Encode signature as base64
    let signature_base64 = base64::encode(signature.as_ref());

    // Get public key as base58
    let public_key = keypair.pubkey().to_string();

    Json(SignMessageResponse {
        success: true,
        data: Some(SignMessageData {
            signature: signature_base64,
            public_key,
            message: req.message,
        }),
        error: None,
    })
}

//--------------------------------------------------------//
#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    success: bool,
    data: Option<VerifyMessageData>,
    error: Option<String>,
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
}

async fn verify_message_handler(
    Json(req): Json<VerifyMessageRequest>,
) -> Json<VerifyMessageResponse> {
    let signature_bytes = match base64::decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(VerifyMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid base64 signature".to_string()),
            });
        }
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return Json(VerifyMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid signature bytes".to_string()),
            });
        }
    };

    let pubkey = match Pubkey::from_str(&req.pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(VerifyMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid pubkey".to_string()),
            });
        }
    };

    let valid = signature.verify(pubkey.as_ref(), req.message.as_bytes());

    Json(VerifyMessageResponse {
        success: true,
        data: Some(VerifyMessageData {
            valid,
            message: req.message,
            pubkey: req.pubkey,
        }),
        error: None,
    })
}
//SEND SOL------------------------------------

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    success: bool,
    data: Option<SendSolData>,
    error: Option<String>,
}

#[derive(Serialize)]
struct SendSolData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

async fn send_sol_handler(Json(req): Json<SendSolRequest>) -> Json<SendSolResponse> {
    // Validate public keys
    let from_pubkey = match Pubkey::from_str(&req.from) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(SendSolResponse {
                success: false,
                data: None,
                error: Some("Invalid sender public key".to_string()),
            });
        }
    };
    let to_pubkey = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(SendSolResponse {
                success: false,
                data: None,
                error: Some("Invalid recipient public key".to_string()),
            });
        }
    };

    // Validate lamports
    if req.lamports == 0 {
        return Json(SendSolResponse {
            success: false,
            data: None,
            error: Some("Lamports must be a positive integer".to_string()),
        });
    }

    // Create the transfer instruction
    let ix = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);

    // Prepare response data
    let program_id = ix.program_id.to_string();
    let accounts = ix
        .accounts
        .iter()
        .map(|meta| meta.pubkey.to_string())
        .collect();
    let instruction_data = base64::encode(ix.data);

    Json(SendSolResponse {
        success: true,
        data: Some(SendSolData {
            program_id,
            accounts,
            instruction_data,
        }),
        error: None,
    })
}

//7. Send token-------------------------------------------------------------------
#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct AccountMetaInfo7Ix {
    pubkey: String,
    isSigner: bool,
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
    data: Option<SendTokenData>,
    error: Option<String>,
}

async fn send_token_handler(Json(req): Json<SendTokenRequest>) -> Json<SendTokenResponse> {
    // Validate pubkeys
    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(SendTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid destination pubkey".to_string()),
            });
        }
    };
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(SendTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid mint pubkey".to_string()),
            });
        }
    };
    let owner = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(SendTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid owner pubkey".to_string()),
            });
        }
    };

    let ix = match transfer_checked(
        &spl_token::id(),
        &destination,
        &mint,
        &destination,
        &owner,
        &[],
        req.amount,
        0,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return Json(SendTokenResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create transfer instruction: {}", e)),
            });
        }
    };

    let accounts = ix
        .accounts
        .iter()
        .map(|meta| AccountMetaInfo {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect();

    let instruction_data = base64::encode(ix.data);

    Json(SendTokenResponse {
        success: true,
        data: Some(SendTokenData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        }),
        error: None,
    })
}

#[tokio::main]
async fn main() {
    let port = 8080;

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let app = Router::new()
        //Working
        .route("/keypair", post(generate_keypair))
        //Working
        .route("/token/create", post(create_token))
        // .route("/token/mint", post(mint_token)); //not working as expected
        // .route("/message/sign", post(sign_message_handler)); //not working as expected
        .route("/message/verify", post(verify_message_handler));
    // .route("/send/sol", post(send_sol_handler));

    let tcp = TcpListener::bind(addr).await.unwrap();
    println!("Server running on {}", addr);
    axum::serve(tcp, app).await.unwrap();
}
