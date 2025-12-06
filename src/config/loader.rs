// Configuration Loader

use crate::config;

use super::schema::Config;
use anyhow::{Context, Result};
use config::{Config as ConfigBuilder, Environment, File};
use std::path::Path;

// ============================================================================
// Configuration Loading
// ============================================================================

pub fn load_config<P: AsRef<Path>>(config_path: P) -> Result<Config> {
    let path_str = config_path
        .as_ref()
        .to_str()
        .context("Config path must be valid UTF-8")?;

    let config = ConfigBuilder::builder()
        .add_source(File::with_name(path_str))
        .add_source(Environment::with_prefix("PORTCULLIS").separator("__"))
        .build()
        .context("Failed to build configuration")?
        .try_deserialize::<Config>()
        .context("Failed to deserialize configuration")?;

    validate_config(&config).context("Configuration validation failed")?;

    Ok(config)
}

// Load configuration with custom environment prefix
pub fn load_config_with_prefix<P: AsRef<Path>>(config_path: P, env_prefix: &str) -> Result<Config> {
    let path_str = config_path
        .as_ref()
        .to_str()
        .context("Config path must be valid UTF-8")?;

    let config = ConfigBuilder::builder()
        .add_source(File::with_name(path_str))
        .add_source(Environment::with_prefix(env_prefix).separator("__"))
        .build()
        .context("Failed to build configuration")?
        .try_deserialize::<Config>()
        .context("Failed to deserialize configuration")?;

    validate_config(&config).context("Configuration validation failed")?;

    Ok(config)
}

// ============================================================================
// Configuration Validation
// ============================================================================

// Validate configuration values
fn validate_config(config: &Config) -> Result<()> {
    // 1. Validate TLS file paths
    validate_file_exists(&config.tls.server_cert, "Server certificate")?;
    validate_file_exists(&config.tls.server_key, "Server private key")?;

    for (idx, ca_cert) in config.tls.client_ca_certs.iter().enumerate() {
        validate_file_exists(ca_cert, &format!("Client CA certificate #{}", idx + 1))?;
    }

    // 2. Validate JWT public key files (if JWT is configured)
    if let Some(jwt_config) = &config.jwt {
        for (idx, public_key) in jwt_config.public_keys.iter().enumerate() {
            match public_key {
                super::schema::JwtPublicKey::RsaPem { path, .. } => {
                    validate_file_exists(path, &format!("JWT RSA public key #{}", idx + 1))?;
                }
                super::schema::JwtPublicKey::EcdsaPem { path, .. } => {
                    validate_file_exists(path, &format!("JWT ECDSA public key #{}", idx + 1))?;
                }
                super::schema::JwtPublicKey::Jwks { .. } => {
                    // JWKS is fetched from URL, no file to validate
                }
            }
        }
    }

    // 3. Validate TLS version
    let valid_tls_versions = ["1.2", "1.3"];
    if !valid_tls_versions.contains(&config.tls.min_tls_version.as_str()) {
        anyhow::bail!(
            "Invalid TLS version: {}. Must be one of: {:?}",
            config.tls.min_tls_version,
            valid_tls_versions
        );
    }

    // 4. Validate backend service names are unique
    validate_unique_backends(config)?;

    // 5. Validate route backends reference existing services
    validate_route_backends(config)?;

    // 6. Validate rate limiting values
    if let Some(rate_limit_config) = &config.rate_limiting {
        for (idx, strategy) in rate_limit_config.strategies.iter().enumerate() {
            if strategy.limit.requests_per_second == 0 {
                anyhow::bail!(
                    "Rate limit strategy #{} has invalid requests_per_second: must be > 0",
                    idx + 1
                );
            }
            if strategy.limit.burst == 0 {
                anyhow::bail!(
                    "Rate limit strategy #{} has invalid burst: must be > 0",
                    idx + 1
                );
            }
        }
    }

    // 7. Validate circuit breaker thresholds
    if let Some(circuit_breaker) = &config.circuit_breaker {
        if circuit_breaker.default.failure_threshold == 0 {
            anyhow::bail!("Circuit breaker default failure_threshold must be > 0");
        }
        if circuit_breaker.default.failure_threshold_percentage > 100 {
            anyhow::bail!(
                "Circuit breaker default failure_threshold_percentage must be <= 100"
            );
        }
        if circuit_breaker.default.success_threshold == 0 {
            anyhow::bail!("Circuit breaker default success_threshold must be > 0");
        }

        // Validate per-backend overrides
        for (backend_name, settings) in &circuit_breaker.backends {
            if settings.failure_threshold == 0 {
                anyhow::bail!(
                    "Circuit breaker for backend '{}' has invalid failure_threshold: must be > 0",
                    backend_name
                );
            }
            if settings.failure_threshold_percentage > 100 {
                anyhow::bail!(
                    "Circuit breaker for backend '{}' has invalid failure_threshold_percentage: must be <= 100",
                    backend_name
                );
            }
            if settings.success_threshold == 0 {
                anyhow::bail!(
                    "Circuit breaker for backend '{}' has invalid success_threshold: must be > 0",
                    backend_name
                );
            }
        }
    }

    // 8. Validate regex patterns in ACL rules
    for (idx, rule) in config.access_control.rules.iter().enumerate() {
        if let Some(cert_cn_regex) = &rule.conditions.cert_cn_regex {
            regex::Regex::new(cert_cn_regex).with_context(|| {
                format!(
                    "Invalid regex pattern in ACL rule #{} ({}): {}",
                    idx + 1,
                    rule.name,
                    cert_cn_regex
                )
            })?;
        }
    }

    // 9. Validate regex patterns in route matches
    for (idx, route) in config.routes.iter().enumerate() {
        if let Some(path_regex) = &route.match_criteria.path_regex {
            regex::Regex::new(path_regex).with_context(|| {
                format!(
                    "Invalid regex pattern in route #{} ({}): {}",
                    idx + 1,
                    route.name,
                    path_regex
                )
            })?;
        }
    }

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

// Validate that a file path exists
fn validate_file_exists<P: AsRef<Path>>(path: P, description: &str) -> Result<()> {
    let path = path.as_ref();

    if !path.exists() {
        anyhow::bail!("{} does not exist: {}", description, path.display());
    }

    if !path.is_file() {
        anyhow::bail!("{} is not a file: {}", description, path.display());
    }

    Ok(())
}

// Validate that all backend names are unique
fn validate_unique_backends(config: &Config) -> Result<()> {
    use std::collections::HashSet;

    let mut seen_names = HashSet::new();

    for service in &config.backends.services {
        if !seen_names.insert(&service.name) {
            anyhow::bail!("Duplicate backend service name: {}", service.name);
        }
    }

    Ok(())
}

// Validate that all route backend references exist
fn validate_route_backends(config: &Config) -> Result<()> {
    use std::collections::HashSet;

    // Collect all backend service names
    let backend_names: HashSet<&str> = config
        .backends
        .services
        .iter()
        .map(|s| s.name.as_str())
        .collect();

    // Check that each route references an existing backend
    for route in &config.routes {
        if !backend_names.contains(route.backend.as_str()) {
            anyhow::bail!(
                "Route '{}' references non-existent backend: {}",
                route.name,
                route.backend
            );
        }
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_valid_config() {
        // TODO: Create a test config file and verify it loads correctly
        todo!("Implement test for valid configuration loading")
    }

    #[test]
    fn test_env_var_override() {
        // TODO: Test that environment variables override file settings
        todo!("Implement test for environment variable override")
    }

    #[test]
    fn test_invalid_config() {
        // TODO: Test that invalid config returns appropriate errors
        todo!("Implement test for invalid configuration")
    }

    #[test]
    fn test_missing_file() {
        // TODO: Test that missing config file returns error
        todo!("Implement test for missing configuration file")
    }
}
