use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

pub mod args;

#[derive(Debug, Clone)]
pub struct AppState {
    pub server_domain: String,
    pub server_addr: SocketAddr,
    pub verifier_addr: String,
    pub max_sent_data: usize,
    pub max_recv_data: usize,
    pub secret: String,
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    #[error("Invalid socket address: {0}")]
    InvalidSocketAddress(String),
}

impl AppState {
    pub fn new(args: &args::Args) -> Result<Self, AppError> {
        let server_ip: IpAddr = args
            .server_addr
            .parse()
            .map_err(|_| AppError::InvalidIpAddress(args.server_addr.clone()))?;

        let server_addr = SocketAddr::new(server_ip, args.server_port);

        Ok(AppState {
            server_domain: args.server_domain.clone(),
            server_addr,
            verifier_addr: args.verifier_addr.clone(),
            max_sent_data: args.max_sent_data,
            max_recv_data: args.max_recv_data,
            secret: args.secret.clone(),
        })
    }
}
