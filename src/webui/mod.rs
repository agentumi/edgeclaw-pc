pub mod handlers;
pub mod http;
pub mod rbac;
pub mod routes;
pub mod static_assets;

use crate::error::AgentError;
use crate::metrics::MetricsRegistry;
use crate::security::{RateLimitConfig, RateLimiter};
use crate::AgentEngine;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

pub use crate::webui::http::{SessionManager, WebUiConfig, SESSION_TTL};

pub struct WebUiServer {
    pub config: WebUiConfig,
    pub engine: Arc<AgentEngine>,
    pub shutdown_tx: Option<broadcast::Sender<()>>,
    pub rate_limiter: Arc<RateLimiter>,
    pub sessions: Arc<SessionManager>,
    pub metrics: Arc<MetricsRegistry>,
}

impl WebUiServer {
    pub fn new(config: WebUiConfig, engine: Arc<AgentEngine>) -> Self {
        Self {
            config,
            engine,
            shutdown_tx: None,
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
            sessions: Arc::new(SessionManager::new()),
            metrics: Arc::new(MetricsRegistry::with_defaults()),
        }
    }

    pub async fn start(&mut self) -> Result<(), AgentError> {
        let listener = TcpListener::bind(&self.config.bind_addr)
            .await
            .map_err(|e| {
                AgentError::ConnectionError(format!(
                    "WebUI failed to bind {}: {}",
                    self.config.bind_addr, e
                ))
            })?;

        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        info!(
            addr = %self.config.bind_addr,
            "Web UI server started"
        );

        loop {
            let mut shutdown_rx = shutdown_tx.subscribe();

            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((mut stream, addr)) => {
                            let engine = Arc::clone(&self.engine);
                            let metrics = Arc::clone(&self.metrics);
                            let limiter = Arc::clone(&self.rate_limiter);
                            let sessions = Arc::clone(&self.sessions);
                            let config = self.config.clone();

                            tokio::spawn(async move {
                                if let Err(e) = routes::handle_connection(
                                    &mut stream,
                                    &engine,
                                    &metrics,
                                    &limiter,
                                    &sessions,
                                    &config
                                ).await {
                                    warn!(peer = %addr, error = %e, "HTTP handler error");
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "WebUI accept error");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Web UI server shutting down");
                    break;
                }
            }
        }

        Ok(())
    }
}
