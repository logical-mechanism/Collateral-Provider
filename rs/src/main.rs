//! Entry point: load configuration, install logging, validate the signing
//! identity, then serve.
//!
//! A misconfigured deploy must fail in the logs rather than 500 on the first
//! POST, so the signing identity is validated before the listener binds.

use std::net::SocketAddr;
use std::process::ExitCode;

use collateral_provider::{config::Config, logging, routes, state::AppState, VERSION};

#[tokio::main]
async fn main() -> ExitCode {
    // `Config::from_env` loads `.env` itself, so there is one documented place
    // where that happens and startup does not walk and parse the file twice.
    //
    // Configuration has to be readable before logging can be configured, so
    // a configuration failure has nowhere to go but stderr.
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("CRITICAL: {err}");
            return ExitCode::FAILURE;
        }
    };

    let _logging = match logging::init(&config) {
        Ok(guard) => guard,
        Err(err) => {
            eprintln!("CRITICAL: {err}");
            return ExitCode::FAILURE;
        }
    };

    let bind_address = config.bind_address;
    let state = match AppState::new(config) {
        Ok(state) => state,
        Err(err) => {
            tracing::error!(target: "api", "CRITICAL: {}", err);
            return ExitCode::FAILURE;
        }
    };

    // The equivalent of `ApiConfig.ready()`: refuse to start rather than
    // discover a broken signing identity on the first POST. Reuses the state's
    // key cache so the check also warms it.
    if let Err(err) = collateral_provider::config::validate_startup(&state.config, &state.keys) {
        tracing::error!(target: "api", "CRITICAL: {}", err);
        return ExitCode::FAILURE;
    }

    let listener = match tokio::net::TcpListener::bind(bind_address).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(target: "api", "CRITICAL: cannot bind {}: {}", bind_address, err);
            return ExitCode::FAILURE;
        }
    };
    // The resolved address, not the requested one: port 0 binds an ephemeral
    // port and an operator needs to see which.
    let bound = listener
        .local_addr()
        .map_or_else(|_| bind_address.to_string(), |address| address.to_string());
    tracing::info!(target: "api", "Collateral provider {} listening on {}", VERSION, bound);

    // `into_make_service_with_connect_info` is what puts the peer address in
    // request extensions; without it every caller shares one throttle bucket.
    let service = routes::app(state).into_make_service_with_connect_info::<SocketAddr>();
    if let Err(err) = axum::serve(listener, service)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!(target: "api", "Server terminated: {}", err);
        return ExitCode::FAILURE;
    }

    tracing::info!(target: "api", "Collateral provider stopped");
    ExitCode::SUCCESS
}

/// Resolve on SIGINT or SIGTERM so an orchestrator's stop signal drains
/// in-flight signing requests instead of dropping them mid-witness.
async fn shutdown_signal() {
    let interrupt = async {
        if tokio::signal::ctrl_c().await.is_err() {
            // Without a working signal handler the only safe behaviour is to
            // never trigger shutdown; the orchestrator's SIGKILL still ends us.
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => tracing::info!(target: "api", "SIGINT received, draining"),
        () = terminate => tracing::info!(target: "api", "SIGTERM received, draining"),
    }
}
