use axum::{
    Json, Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    // Get port from Render environment variable (default to 8080 for local dev)
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port)); // Bind to 0.0.0.0

    let router = Router::new()
        .route("/", get(test_route))
        .route("/post", post(post_handler));

    let tcp = TcpListener::bind(addr).await.unwrap();
    println!("Server running on {}", addr);
    axum::serve(tcp, router).await.unwrap();
}

async fn test_route() -> &'static str {
    "Hello from test function"
}

async fn post_handler(Json(item): Json<Person>) -> Json<Person> {
    Json(item)
}

#[derive(Debug, Serialize, Deserialize)]
struct Person {
    name: String,
    age: u16,
}
