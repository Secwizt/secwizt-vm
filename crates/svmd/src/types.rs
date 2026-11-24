use serde_json::{json, Value};
use std::{error::Error, fmt, io};

#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
}
impl ApiError {
    pub fn new(status: u16, code: &str, message: impl Into<String>) -> Self {
        Self { status, code: code.to_owned(), message: message.into() }
    }
    pub fn storage(_: io::Error) -> Self {
        Self::new(500, "storage", "The service could not read or save its local data. Check the folder permissions and free space.")
    }
    pub fn missing() -> Self { Self::new(404, "not_found", "This API resource does not exist.") }
    pub fn invalid(message: &str) -> Self { Self::new(400, "invalid_request", message) }
}
impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.message) }
}
impl Error for ApiError {}

pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub width_height: Option<(u16, u16)>,
    pub body: Vec<u8>,
}
impl Reply {
    pub fn json(value: Value) -> Self { Self::json_status(200, value) }
    pub fn created(value: Value) -> Self { Self::json_status(201, value) }
    pub(crate) fn json_status(status: u16, value: Value) -> Self {
        Self { status, content_type: "application/json", width_height: None, body: value.to_string().into_bytes() }
    }
    pub fn rgba(width: u16, height: u16, pixels: Vec<u8>) -> Self {
        Self { status: 200, content_type: "application/octet-stream", width_height: Some((width, height)), body: pixels }
    }
    pub(crate) fn error(error: ApiError) -> Self {
        Self::json_status(error.status, json!({"error":{"code":error.code,"message":error.message}}))
    }
}
