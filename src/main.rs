use axum::{
    Json, Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let router = Router::new().route("/", get(test_route))
    .route("/post", post(post_handler));
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let tcp = TcpListener::bind(&addr).await.unwrap();
    axum::serve(tcp, router).await.unwrap();
}

async fn test_route() -> &'static str {
    "Hello from test function"
}

async fn post_handler(Json(item):Json<Person>)->Json<Person>{
    Json(item)
}

#[derive(Debug, Serialize, Deserialize)]
struct Person {
    name: String,
    age: u16,
}
