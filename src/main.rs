mod cache;
mod config;
mod geo;
mod handler;
mod lists;
mod poison;
mod probe;
mod rank;
mod recurse;
mod resolve;
mod siblings;
mod upstream;

use std::sync::Arc;
use std::time::Duration;

use hickory_proto::rr::{LowerName, Name};
use hickory_server::Server;
use hickory_server::zone_handler::{Catalog, ZoneHandler};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    probe::install_crypto_provider();

    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());
    let config = config::Config::load(&path);
    let listen = config.listen;
    let engine = resolve::Engine::open(config);
    let origin = LowerName::from(Name::root());
    let handler: Arc<dyn ZoneHandler> = Arc::new(handler::Handler::new(engine));

    let mut catalog = Catalog::new();
    catalog.upsert(origin, vec![handler]);

    let udp = tokio::net::UdpSocket::bind(listen).await?;
    let tcp = tokio::net::TcpListener::bind(listen).await?;

    let mut server = Server::new(catalog);
    server.register_socket(udp);
    server.register_listener(tcp, Duration::from_secs(5), 4096);
    tracing::info!(%listen, "opinionated resolver listening");
    server.block_until_done().await?;
    Ok(())
}
