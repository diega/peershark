use axum::http::{Method, header};
use axum::{
    Json, Router,
    extract::{ConnectInfo, State, WebSocketUpgrade},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use axum_extra::headers::authorization::{Authorization, Bearer};
use axum_extra::typed_header::TypedHeader;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use time::Duration;
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, info, warn};

use crate::error::Error;
use crate::event_bus::EventBus;
use crate::events::{Direction, ProxyEvent};

use super::auth;
use super::state::{ApiState, MAX_WS_CONNECTIONS};
use super::websocket;

/// Rate limiter type alias for clarity.
pub type IpRateLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub api: ApiState,
    pub event_bus: Arc<EventBus>,
    pub rate_limiter: Arc<IpRateLimiter>,
}

/// Start the API HTTP server.
pub async fn run_server(
    port: u16,
    bind_address: Option<String>,
    cors_origin: Option<String>,
    api_state: ApiState,
    event_bus: Arc<EventBus>,
    event_rx: broadcast::Receiver<ProxyEvent>,
) -> Result<(), Error> {
    // Spawn state updater with pre-subscribed receiver to avoid race condition
    spawn_state_updater(api_state.clone(), event_rx);

    // Create rate limiter: 10 requests per second per IP
    let rate_limiter = Arc::new(RateLimiter::keyed(Quota::per_second(
        NonZeroU32::new(10).expect("10 > 0"),
    )));

    let state = AppState {
        api: api_state,
        event_bus,
        rate_limiter,
    };

    let cors = match cors_origin {
        Some(origin) if origin == "*" => {
            if std::env::var("PEERSHARK_ALLOW_CORS_ANY").is_err() {
                return Err(Error::Protocol(
                    "CORS '*' requires PEERSHARK_ALLOW_CORS_ANY=1 environment variable".to_string(),
                ));
            }
            warn!(
                "CORS origin is '*' - cookies will NOT work! Use specific origin for cookie auth."
            );
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
            // Note: allow_credentials(true) is incompatible with wildcard origin
        }
        Some(origin) => {
            let header_value: HeaderValue = origin
                .parse()
                .map_err(|_| Error::Protocol(format!("invalid CORS origin: {}", origin)))?;
            CorsLayer::new()
                .allow_origin(header_value)
                .allow_credentials(true)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        }
        None => CorsLayer::new()
            .allow_credentials(true)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
    };

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/api/auth", post(auth_handler))
        .route("/api/state", get(state_handler))
        .route("/ws", get(ws_handler))
        .layer(cors)
        .with_state(state);

    // Default to localhost for security (prevents external access by default)
    let bind_addr = bind_address.as_deref().unwrap_or("127.0.0.1");
    let addr: SocketAddr = format!("{}:{}", bind_addr, port)
        .parse()
        .map_err(|e| Error::Protocol(format!("invalid bind address: {}", e)))?;
    info!(%addr, "API server listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Io(format!("failed to bind API server: {}", e)))?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| Error::Io(format!("API server error: {}", e)))
}

/// Health check endpoint (no auth required).
async fn health_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let client_ip = addr.ip().to_string();
    if state.rate_limiter.check_key(&client_ip).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    "ok".into_response()
}

/// Authentication endpoint - exchanges Bearer token for HttpOnly cookie.
async fn auth_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
) -> Response {
    // Rate limit
    let client_ip = addr.ip().to_string();
    if state.rate_limiter.check_key(&client_ip).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }

    // Require auth to be enabled
    let secret = match &state.api.jwt_secret {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "auth disabled").into_response(),
    };

    // Get token from Authorization header
    let token = match auth_header {
        Some(TypedHeader(Authorization(bearer))) => bearer.token().to_string(),
        None => return (StatusCode::UNAUTHORIZED, "missing authorization header").into_response(),
    };

    // Validate token
    if let Err(e) = auth::validate_token(&token, secret) {
        warn!(error = %e, "invalid token in auth request");
        return (StatusCode::UNAUTHORIZED, "invalid token").into_response();
    }

    // Create secure cookie
    let cookie = Cookie::build(("peershark_session", token))
        .path("/")
        .http_only(true)
        .secure(!cfg!(debug_assertions))
        .same_site(SameSite::Strict)
        .max_age(Duration::hours(24))
        .build();

    (jar.add(cookie), StatusCode::OK).into_response()
}

/// Get current state (auth required via cookie or header unless --no-auth).
async fn state_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
) -> Response {
    // Check rate limit
    let client_ip = addr.ip().to_string();
    if state.rate_limiter.check_key(&client_ip).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }

    // Skip auth if disabled
    if let Some(secret) = &state.api.jwt_secret {
        // Try cookie first, then Authorization header
        let token = if let Some(cookie) = jar.get("peershark_session") {
            cookie.value().to_string()
        } else if let Some(TypedHeader(Authorization(bearer))) = auth_header {
            bearer.token().to_string()
        } else {
            return (StatusCode::UNAUTHORIZED, "missing credentials").into_response();
        };

        if let Err(e) = auth::validate_token(&token, secret) {
            warn!(error = %e, "invalid token");
            return (StatusCode::UNAUTHORIZED, "invalid token").into_response();
        }
    }

    let snapshot = state.api.snapshot().await;
    Json(snapshot).into_response()
}

/// WebSocket upgrade handler (auth via cookie or header unless --no-auth).
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
) -> Response {
    // Check rate limit
    let client_ip = addr.ip().to_string();
    if state.rate_limiter.check_key(&client_ip).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }

    // Check WebSocket connection limit
    let current_ws = state.api.ws_connections.load(Ordering::Relaxed);
    if current_ws >= MAX_WS_CONNECTIONS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many WebSocket connections",
        )
            .into_response();
    }

    // Skip auth if disabled
    if let Some(secret) = &state.api.jwt_secret {
        // Try cookie first, then Authorization header
        let token = if let Some(cookie) = jar.get("peershark_session") {
            cookie.value().to_string()
        } else if let Some(TypedHeader(Authorization(bearer))) = auth_header {
            bearer.token().to_string()
        } else {
            return (StatusCode::UNAUTHORIZED, "missing credentials").into_response();
        };

        if let Err(e) = auth::validate_token(&token, secret) {
            warn!(error = %e, "invalid WebSocket credentials");
            return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
        }
    }

    // Increment connection count
    state.api.ws_connections.fetch_add(1, Ordering::Relaxed);

    let api_state = state.api.clone();
    let event_rx = state.event_bus.subscribe();

    ws.on_upgrade(move |socket| async move {
        websocket::handle_socket(socket, api_state.clone(), event_rx).await;
        // Decrement connection count when done
        api_state.ws_connections.fetch_sub(1, Ordering::Relaxed);
    })
}

/// Spawn a background task that updates API state from events.
fn spawn_state_updater(state: ApiState, mut event_rx: broadcast::Receiver<ProxyEvent>) {
    tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(event) => match event {
                    ProxyEvent::PeerConnected {
                        tunnel_id,
                        client_node_id,
                        client_id,
                        remote_enode,
                        network_id,
                        fork_hash,
                        fork_next,
                        capabilities,
                        ..
                    } => {
                        state
                            .add_tunnel(
                                tunnel_id,
                                client_node_id,
                                client_id,
                                remote_enode,
                                network_id,
                                fork_hash,
                                fork_next,
                                capabilities,
                            )
                            .await;
                        debug!("tunnel added to state");
                    }
                    ProxyEvent::PeerDisconnected { tunnel_id, .. } => {
                        state.remove_tunnel(&tunnel_id).await;
                        debug!("tunnel removed from state");
                    }
                    ProxyEvent::MessageRelayed {
                        tunnel_id,
                        direction,
                        size,
                        ..
                    } => {
                        let (bytes_in, bytes_out) = match direction {
                            Direction::PeerToClient => (size as u64, 0),
                            Direction::ClientToPeer => (0, size as u64),
                        };
                        state.record_transfer(&tunnel_id, bytes_in, bytes_out).await;
                    }
                    ProxyEvent::ConnectionAttemptFailed { .. } | ProxyEvent::TrafficTick { .. } => {
                        // Connection attempts and traffic ticks don't update state
                    }
                },
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(missed = n, "state updater lagged behind");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    debug!("event bus closed, stopping state updater");
                    break;
                }
            }
        }
    });
}
