use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("config: {0}")]
    Config(String),
    #[error("store: {0}")]
    Store(String),
    #[error("firewall: {0}")]
    Firewall(String),
    #[error("honeypot: {0}")]
    Honeypot(String),
    #[error("ai: {0}")]
    Ai(String),
    #[error("api: {0}")]
    Api(String),
}

pub type Result<T> = std::result::Result<T, Error>;
