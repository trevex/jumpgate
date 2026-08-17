//! jumpgate gateway: the single externally exposed data-plane entrypoint.
//! M1 serves only `/healthz`; token validation and session load-balancing
//! arrive in M4.

mod health;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let addr =
        std::env::var("JUMPGATE_GATEWAY_LISTEN").unwrap_or_else(|_| "0.0.0.0:8443".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "gateway listening");
    axum::serve(listener, health::router()).await?;
    Ok(())
}
