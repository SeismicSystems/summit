use std::num::ParseIntError;

#[derive(Debug)]
pub enum ClientError {
    Request(reqwest::Error),
    Parse(ParseIntError),
}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        ClientError::Request(e)
    }
}

impl From<ParseIntError> for ClientError {
    fn from(e: ParseIntError) -> Self {
        ClientError::Parse(e)
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Request(e) => write!(f, "request error: {}", e),
            ClientError::Parse(e) => write!(f, "parse error: {}", e),
        }
    }
}

impl std::error::Error for ClientError {}
