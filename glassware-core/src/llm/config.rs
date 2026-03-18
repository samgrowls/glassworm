//! LLM Configuration Module
//!
//! Configuration for the LLM analysis layer. All values come from environment
//! variables (with .env support via dotenvy).

use std::env;

/// Configuration for the LLM analysis layer.
/// All values come from environment variables (with .env support via dotenvy).
#[derive(Debug, Clone)]
pub struct LlmConfig {
    /// OpenAI-compatible API base URL
    /// e.g. "https://api.cerebras.ai/v1", "https://api.openai.com/v1"
    pub base_url: String,
    /// API key for the provider
    pub api_key: String,
    /// Model identifier (defaults to "llama-3.3-70b" if unset)
    pub model: String,
}

/// Errors that can occur when loading LLM configuration
#[derive(Debug)]
pub enum LlmConfigError {
    MissingBaseUrl,
    MissingApiKey,
}

impl std::fmt::Display for LlmConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LlmConfigError::MissingBaseUrl => write!(
                f,
                "Missing GLASSWARE_LLM_BASE_URL. Set it in .env or as an environment variable."
            ),
            LlmConfigError::MissingApiKey => write!(
                f,
                "Missing GLASSWARE_LLM_API_KEY. Set it in .env or as an environment variable."
            ),
        }
    }
}

impl std::error::Error for LlmConfigError {}

impl LlmConfig {
    /// Load configuration from environment variables.
    ///
    /// Silently tries to load .env file first (if present), then reads from env.
    /// Returns an error if required variables are missing.
    pub fn from_env() -> Result<Self, LlmConfigError> {
        // Try to load .env file (silently ignore if missing)
        let _ = dotenvy::dotenv();

        let base_url = env::var("GLASSWARE_LLM_BASE_URL")
            .map(|url| url.trim_end_matches('/').to_string())
            .map_err(|_| LlmConfigError::MissingBaseUrl)?;

        let api_key =
            env::var("GLASSWARE_LLM_API_KEY").map_err(|_| LlmConfigError::MissingApiKey)?;

        // Default model if not specified
        let model = env::var("GLASSWARE_LLM_MODEL").unwrap_or_else(|_| "llama-3.3-70b".to_string());

        Ok(Self {
            base_url,
            api_key,
            model,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env_missing_base_url() {
        // Clear the env var if set
        env::remove_var("GLASSWARE_LLM_BASE_URL");
        env::set_var("GLASSWARE_LLM_API_KEY", "test-key");

        let result = LlmConfig::from_env();
        assert!(matches!(result, Err(LlmConfigError::MissingBaseUrl)));

        env::remove_var("GLASSWARE_LLM_API_KEY");
    }

    #[test]
    fn test_config_from_env_missing_api_key() {
        env::set_var("GLASSWARE_LLM_BASE_URL", "https://api.test.com/v1");
        env::remove_var("GLASSWARE_LLM_API_KEY");

        let result = LlmConfig::from_env();
        assert!(matches!(result, Err(LlmConfigError::MissingApiKey)));

        env::remove_var("GLASSWARE_LLM_BASE_URL");
    }

    #[test]
    fn test_config_from_env_success() {
        env::set_var("GLASSWARE_LLM_BASE_URL", "https://api.test.com/v1/");
        env::set_var("GLASSWARE_LLM_API_KEY", "test-key");
        env::set_var("GLASSWARE_LLM_MODEL", "test-model");

        let config = LlmConfig::from_env().unwrap();
        assert_eq!(config.base_url, "https://api.test.com/v1"); // trailing slash stripped
        assert_eq!(config.api_key, "test-key");
        assert_eq!(config.model, "test-model");

        env::remove_var("GLASSWARE_LLM_BASE_URL");
        env::remove_var("GLASSWARE_LLM_API_KEY");
        env::remove_var("GLASSWARE_LLM_MODEL");
    }

    #[test]
    fn test_config_default_model() {
        env::set_var("GLASSWARE_LLM_BASE_URL", "https://api.test.com/v1");
        env::set_var("GLASSWARE_LLM_API_KEY", "test-key");
        env::remove_var("GLASSWARE_LLM_MODEL");

        let config = LlmConfig::from_env().unwrap();
        assert_eq!(config.model, "llama-3.3-70b");

        env::remove_var("GLASSWARE_LLM_BASE_URL");
        env::remove_var("GLASSWARE_LLM_API_KEY");
    }
}
