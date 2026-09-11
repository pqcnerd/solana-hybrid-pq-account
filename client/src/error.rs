//! Client-side errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("not implemented in Milestone 0: {0}")]
    Unimplemented(&'static str),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ClientError>;
