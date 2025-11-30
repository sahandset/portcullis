// Defines all error types

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::fmt;
use thiserror::Error;

// ============================================================================
// Main Error Type
// ============================================================================

// Main error type
#[derive(Debug, Error)]
pub enum PortcullisError {
    // ------------------------------------------------------------------------
    // Configuration Errors
    // ------------------------------------------------------------------------
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    // ------------------------------------------------------------------------
    // TLS and Certificate Errors
    // ------------------------------------------------------------------------
    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Certificate validation failed: {0}")]
    CertificateValidation(String),

    #[error("Certificate expired")]
    CertificateExpired,

    #[error("Certificate revoked")]
    CertificateRevoked,

    #[error("Invalid certificate chain")]
    InvalidCertChain,

    #[error("CRL check failed: {0}")]
    CrlCheckFailed(String),

    #[error("OCSP check failed: {0}")]
    OcspCheckFailed(String),

    // ------------------------------------------------------------------------
    // Authentication Errors
    // ------------------------------------------------------------------------
    #[error("Authentication required")]
    AuthenticationRequired,

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Invalid JWT: {0}")]
    InvalidJwt(String),

    #[error("JWT expired")]
    JwtExpired,

    #[error("Invalid API key")]
    InvalidApiKey,

    #[error("Invalid HMAC signature")]
    InvalidHmacSignature,

    // ------------------------------------------------------------------------
    // Authorization Errors
    // ------------------------------------------------------------------------
    #[error("Access denied")]
    AccessDenied,

    #[error("Insufficient permissions")]
    InsufficientPermissions,

    // ------------------------------------------------------------------------
    // Rate Limiting Errors
    // ------------------------------------------------------------------------
    #[error("Rate limit exceeded")]
    RateLimitExceeded { retry_after_secs: Option<u64> },

    // ------------------------------------------------------------------------
    // Circuit Breaker Errors
    // ------------------------------------------------------------------------
    #[error("Circuit breaker open for backend: {0}")]
    CircuitBreakerOpen(String),

    // ------------------------------------------------------------------------
    // Replay Protection Errors
    // ------------------------------------------------------------------------
    #[error("Request expired (timestamp too old)")]
    RequestExpired,

    #[error("Nonce already used (replay attack detected)")]
    NonceReused,

    #[error("Invalid timestamp")]
    InvalidTimestamp,

    // ------------------------------------------------------------------------
    // Backend/Proxy Errors
    // ------------------------------------------------------------------------
    #[error("Backend not found: {0}")]
    BackendNotFound(String),

    #[error("All backends unavailable")]
    AllBackendsUnavailable,

    #[error("Backend error: {0}")]
    BackendError(String),

    #[error("Backend timeout")]
    BackendTimeout,

    // ------------------------------------------------------------------------
    // HTTP/Request Errors
    // ------------------------------------------------------------------------
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Request too large")]
    RequestTooLarge,

    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    #[error("Route not found")]
    RouteNotFound,

    // ------------------------------------------------------------------------
    // Internal Errors
    // ------------------------------------------------------------------------
    #[error("Internal server error")]
    InternalError,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

// ============================================================================
// HTTP Response Conversion
// ============================================================================

impl IntoResponse for PortcullisError {
    // Convert error into an HTTP Response
    fn into_response(self) -> Response {
        let status = match self {
            // Authentication errors -> 401 Unauthorized
            Self::AuthenticationRequired
            | Self::AuthenticationFailed(_)
            | Self::InvalidJwt(_)
            | Self::JwtExpired
            | Self::InvalidApiKey
            | Self::InvalidHmacSignature => StatusCode::UNAUTHORIZED,

            // Authorization errors -> 403 Forbidden
            Self::AccessDenied
            | Self::InsufficientPermissions
            | Self::CertificateValidation(_)
            | Self::CertificateExpired
            | Self::CertificateRevoked
            | Self::InvalidCertChain
            | Self::NonceReused => StatusCode::FORBIDDEN,

            // Bad Request -> 400
            Self::InvalidRequest(_)
            | Self::InvalidHeader(_)
            | Self::InvalidTimestamp
            | Self::RequestExpired => StatusCode::BAD_REQUEST,

            // Not Found -> 404
            Self::RouteNotFound | Self::BackendNotFound(_) => StatusCode::NOT_FOUND,

            // Payload Too Large -> 413
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,

            // Rate Limiting -> 429
            Self::RateLimitExceeded { .. } => StatusCode::TOO_MANY_REQUESTS,

            // Internal Server Error -> 500
            Self::InternalError
            | Self::Io(_)
            | Self::Config(_)
            | Self::InvalidConfig(_)
            | Self::Tls(_)
            | Self::CrlCheckFailed(_)
            | Self::OcspCheckFailed(_)
            | Self::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,

            // Bad Gateway -> 502
            Self::BackendError(_) => StatusCode::BAD_GATEWAY,

            // Service Unavailable -> 503
            Self::AllBackendsUnavailable | Self::CircuitBreakerOpen(_) => {
                StatusCode::SERVICE_UNAVAILABLE
            }

            // Gateway Timeout -> 504
            Self::BackendTimeout => StatusCode::GATEWAY_TIMEOUT,
        };

        tracing::error!("Request failed: {}", self);

        let body = Json(json!({
            "error": self.error_code(),
            "message": self.user_message()
        }));

        (status, body).into_response()
    }
}

// ============================================================================
// Helper Methods
// ============================================================================

impl PortcullisError {
    // Get HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            // Authentication errors -> 401 Unauthorized
            Self::AuthenticationRequired
            | Self::AuthenticationFailed(_)
            | Self::InvalidJwt(_)
            | Self::JwtExpired
            | Self::InvalidApiKey
            | Self::InvalidHmacSignature => StatusCode::UNAUTHORIZED,

            // Authorization errors -> 403 Forbidden
            Self::AccessDenied
            | Self::InsufficientPermissions
            | Self::CertificateValidation(_)
            | Self::CertificateExpired
            | Self::CertificateRevoked
            | Self::InvalidCertChain
            | Self::NonceReused => StatusCode::FORBIDDEN,

            // Bad Request -> 400
            Self::InvalidRequest(_)
            | Self::InvalidHeader(_)
            | Self::InvalidTimestamp
            | Self::RequestExpired => StatusCode::BAD_REQUEST,

            // Not Found -> 404
            Self::RouteNotFound | Self::BackendNotFound(_) => StatusCode::NOT_FOUND,

            // Payload Too Large -> 413
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,

            // Rate Limiting -> 429
            Self::RateLimitExceeded { .. } => StatusCode::TOO_MANY_REQUESTS,

            // Internal Server Error -> 500
            Self::InternalError
            | Self::Io(_)
            | Self::Config(_)
            | Self::InvalidConfig(_)
            | Self::Tls(_)
            | Self::CrlCheckFailed(_)
            | Self::OcspCheckFailed(_)
            | Self::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,

            // Bad Gateway -> 502
            Self::BackendError(_) => StatusCode::BAD_GATEWAY,

            // Service Unavailable -> 503
            Self::AllBackendsUnavailable | Self::CircuitBreakerOpen(_) => {
                StatusCode::SERVICE_UNAVAILABLE
            }

            // Gateway Timeout -> 504
            Self::BackendTimeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    // Get the error code description for this error
    pub fn error_code(&self) -> &str {
        match self {
            // Configuration Errors
            Self::Config(_) => "config_error",
            Self::InvalidConfig(_) => "invalid_config",

            // TLS and Certificate Errors
            Self::Tls(_) => "tls_error",
            Self::CertificateValidation(_) => "certificate_validation_failed",
            Self::CertificateExpired => "certificate_expired",
            Self::CertificateRevoked => "certificate_revoked",
            Self::InvalidCertChain => "invalid_cert_chain",
            Self::CrlCheckFailed(_) => "crl_check_failed",
            Self::OcspCheckFailed(_) => "ocsp_check_failed",

            // Authentication Errors
            Self::AuthenticationRequired => "authentication_required",
            Self::AuthenticationFailed(_) => "authentication_failed",
            Self::InvalidJwt(_) => "invalid_jwt",
            Self::JwtExpired => "jwt_expired",
            Self::InvalidApiKey => "invalid_api_key",
            Self::InvalidHmacSignature => "invalid_hmac_signature",

            // Authorization Errors
            Self::AccessDenied => "access_denied",
            Self::InsufficientPermissions => "insufficient_permissions",

            // Rate Limiting Errors
            Self::RateLimitExceeded { .. } => "rate_limit_exceeded",

            // Circuit Breaker Errors
            Self::CircuitBreakerOpen(_) => "circuit_breaker_open",

            // Replay Protection Errors
            Self::RequestExpired => "request_expired",
            Self::NonceReused => "nonce_reused",
            Self::InvalidTimestamp => "invalid_timestamp",

            // Backend/Proxy Errors
            Self::BackendNotFound(_) => "backend_not_found",
            Self::AllBackendsUnavailable => "all_backends_unavailable",
            Self::BackendError(_) => "backend_error",
            Self::BackendTimeout => "backend_timeout",

            // HTTP/Request Errors
            Self::InvalidRequest(_) => "invalid_request",
            Self::RequestTooLarge => "request_too_large",
            Self::InvalidHeader(_) => "invalid_header",
            Self::RouteNotFound => "route_not_found",

            // Internal Errors
            Self::InternalError => "internal_error",
            Self::Io(_) => "io_error",

            Self::Other(_) => "unknown_error",
        }
    }

    // Determine if the error is system-related
    pub fn is_unexpected(&self) -> bool {
        match self {
            // Expected errors - normal operation
            Self::RateLimitExceeded { .. }
            | Self::AuthenticationRequired
            | Self::AuthenticationFailed(_)
            | Self::InvalidJwt(_)
            | Self::JwtExpired
            | Self::InvalidApiKey
            | Self::InvalidHmacSignature
            | Self::AccessDenied
            | Self::InsufficientPermissions
            | Self::CertificateValidation(_)
            | Self::CertificateExpired
            | Self::CertificateRevoked
            | Self::InvalidCertChain
            | Self::NonceReused
            | Self::RequestExpired
            | Self::InvalidTimestamp
            | Self::InvalidRequest(_)
            | Self::InvalidHeader(_)
            | Self::RequestTooLarge
            | Self::RouteNotFound
            | Self::BackendNotFound(_) => false,

            // Unexpected errors - indicate system problems
            Self::Config(_)
            | Self::InvalidConfig(_)
            | Self::Tls(_)
            | Self::CrlCheckFailed(_)
            | Self::OcspCheckFailed(_)
            | Self::InternalError
            | Self::Io(_)
            | Self::BackendError(_)
            | Self::BackendTimeout
            | Self::AllBackendsUnavailable
            | Self::CircuitBreakerOpen(_)
            | Self::Other(_) => true,
        }
    }

    // Get user-safe error message
    pub fn user_message(&self) -> String {
        match self {
            // Authentication errors
            Self::AuthenticationRequired => "Authentication required".to_string(),
            Self::AuthenticationFailed(_) => "Authentication failed".to_string(),
            Self::InvalidJwt(_) => "Invalid authentication token".to_string(),
            Self::JwtExpired => "Authentication token expired".to_string(),
            Self::InvalidApiKey => "Invalid API key".to_string(),
            Self::InvalidHmacSignature => "Invalid request signature".to_string(),

            // Authorization errors
            Self::AccessDenied => "Access denied".to_string(),
            Self::InsufficientPermissions => "Insufficient permissions".to_string(),

            // Certificate errors
            Self::CertificateValidation(_) => "Certificate validation failed".to_string(),
            Self::CertificateExpired => "Certificate expired".to_string(),
            Self::CertificateRevoked => "Certificate revoked".to_string(),
            Self::InvalidCertChain => "Invalid certificate".to_string(),

            // Rate limiting
            Self::RateLimitExceeded { retry_after_secs } => {
                if let Some(secs) = retry_after_secs {
                    format!("Rate limit exceeded. Please try again in {} seconds", secs)
                } else {
                    "Rate limit exceeded. Please try again later".to_string()
                }
            }

            // Replay protection
            Self::RequestExpired => "Request expired".to_string(),
            Self::NonceReused => "Invalid request".to_string(),
            Self::InvalidTimestamp => "Invalid request timestamp".to_string(),

            // Client request errors
            Self::InvalidRequest(_) => "Invalid request".to_string(),
            Self::InvalidHeader(_) => "Invalid request header".to_string(),
            Self::RequestTooLarge => "Request too large".to_string(),
            Self::RouteNotFound => "Route not found".to_string(),
            Self::BackendNotFound(_) => "Resource not found".to_string(),

            // Backend/system errors
            Self::BackendError(_) => "Service temporarily unavailable".to_string(),
            Self::BackendTimeout => "Service timeout. Please try again".to_string(),
            Self::AllBackendsUnavailable => "Service temporarily unavailable".to_string(),
            Self::CircuitBreakerOpen(_) => "Service temporarily unavailable".to_string(),

            // Internal errors
            Self::Config(_) => "Internal server error".to_string(),
            Self::InvalidConfig(_) => "Internal server error".to_string(),
            Self::Tls(_) => "Internal server error".to_string(),
            Self::CrlCheckFailed(_) => "Internal server error".to_string(),
            Self::OcspCheckFailed(_) => "Internal server error".to_string(),
            Self::InternalError => "Internal server error".to_string(),
            Self::Io(_) => "Internal server error".to_string(),
            Self::Other(_) => "An error occurred".to_string(),
        }
    }
}

// ============================================================================
// Error Conversions
// ============================================================================

// Convert from rustls::Error
impl From<rustls::Error> for PortcullisError {
    fn from(err: rustls::Error) -> Self {
        use rustls::Error as RE;

        match err {
            // Certificate-related errors
            RE::InvalidCertificate(cert_err) => {
                Self::CertificateValidation(format!("Invalid certificate: {:?}", cert_err))
            }
            RE::NoCertificatesPresented => {
                Self::CertificateValidation("No certificates presented".to_string())
            }

            // Catch all other TLS errors
            _ => Self::Tls(format!("TLS error: {}", err)),
        }
    }
}

// Convert from jsonwebtoken::errors::Error
impl From<jsonwebtoken::errors::Error> for PortcullisError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;

        match err.kind() {
            ErrorKind::ExpiredSignature => Self::JwtExpired,
            ErrorKind::InvalidToken => Self::InvalidJwt("Invalid token format".to_string()),
            ErrorKind::InvalidSignature => Self::InvalidJwt("Invalid signature".to_string()),
            ErrorKind::InvalidIssuer => Self::InvalidJwt("Invalid issuer".to_string()),
            ErrorKind::InvalidAudience => Self::InvalidJwt("Invalid audience".to_string()),
            _ => Self::InvalidJwt(format!("JWT error: {}", err)),
        }
    }
}

// Convert from hyper::Error
impl From<hyper::Error> for PortcullisError {
    fn from(err: hyper::Error) -> Self {
        if err.is_timeout() {
            Self::BackendTimeout
        } else if err.is_connect() {
            Self::BackendError(format!("Connection error: {}", err))
        } else {
            Self::BackendError(format!("HTTP error: {}", err))
        }
    }
}

// Convert from reqwest::Error (used for CRL/OCSP fetching)
impl From<reqwest::Error> for PortcullisError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            Self::CrlCheckFailed("Timeout fetching CRL/OCSP".to_string())
        } else if err.is_connect() {
            Self::CrlCheckFailed(format!("Connection failed: {}", err))
        } else if err.is_status() {
            Self::CrlCheckFailed(format!("HTTP error: {}", err))
        } else {
            Self::CrlCheckFailed(format!("Request error: {}", err))
        }
    }
}

// ============================================================================
// Result Type Alias
// ============================================================================

// Result type alias for Portcullis operations
pub type Result<T> = std::result::Result<T, PortcullisError>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        // TODO: Test that each error maps to correct HTTP status code
        todo!("Implement error status code tests")
    }

    #[test]
    fn test_error_codes() {
        // TODO: Test that error codes are consistent and machine-readable
        todo!("Implement error code tests")
    }

    #[test]
    fn test_user_messages_safe() {
        // TODO: Verify user messages don't leak sensitive information
        todo!("Implement user message safety tests")
    }

    #[test]
    fn test_error_conversions() {
        // TODO: Test From implementations work correctly
        todo!("Implement error conversion tests")
    }
}
