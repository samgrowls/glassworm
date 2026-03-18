//! LLM Analyzer Module
//!
//! Provides the OpenAI-compatible analyzer for reviewing flagged files.

use crate::finding::Finding;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

use super::config::LlmConfig;

/// Verdict returned by the LLM for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmVerdict {
    pub is_malicious: bool,
    pub confidence: f64,
    pub reasoning: String,
    pub reclassified_severity: Option<String>,
}

/// Result of LLM analysis for one file. Pairs the file path with the verdict.
#[derive(Debug, Clone)]
pub struct LlmFileResult {
    pub file_path: std::path::PathBuf,
    pub verdict: LlmVerdict,
}

/// Errors that can occur during LLM analysis
#[derive(Debug)]
pub enum LlmError {
    Config(super::config::LlmConfigError),
    Http(reqwest::Error),
    ApiError {
        status: u16,
        body: String,
    },
    ParseError {
        raw_content: String,
        source: serde_json::Error,
    },
}

impl std::fmt::Display for LlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LlmError::Config(e) => write!(f, "Configuration error: {}", e),
            LlmError::Http(e) => write!(f, "HTTP error: {}", e),
            LlmError::ApiError { status, body } => {
                write!(f, "API error (status {}): {}", status, body)
            }
            LlmError::ParseError {
                raw_content,
                source,
            } => {
                write!(f, "Parse error: {}\nRaw content: {}", source, raw_content)
            }
        }
    }
}

impl std::error::Error for LlmError {}

impl From<super::config::LlmConfigError> for LlmError {
    fn from(err: super::config::LlmConfigError) -> Self {
        LlmError::Config(err)
    }
}

impl From<reqwest::Error> for LlmError {
    fn from(err: reqwest::Error) -> Self {
        LlmError::Http(err)
    }
}

/// System prompt for the LLM malware analyst
const SYSTEM_PROMPT: &str = r#"You are a malware analyst specializing in JavaScript/TypeScript supply chain attacks.
You are reviewing a file from an npm package that was flagged by static analysis.

Your task: determine whether the flagged code is genuinely malicious or a false positive.

Focus on these attack patterns:
- Data exfiltration (credentials, environment variables, SSH keys, tokens)
- Encrypted or obfuscated payload decryption followed by dynamic execution
- Command-and-control communication disguised as normal HTTP traffic
- Steganographic data hiding (payloads in images, fonts, or other binary files)
- Abuse of package lifecycle scripts (preinstall/postinstall) for code execution
- Hand-rolled cryptography used to evade API-level detection

Respond with ONLY a JSON object (no markdown, no explanation outside the JSON):
{
  "is_malicious": true/false,
  "confidence": 0.0 to 1.0,
  "reasoning": "your concise analysis (2-4 sentences)",
  "reclassified_severity": "Critical" | "High" | "Medium" | "Low" | "Info" | null
}

If reclassified_severity is null, the original severity stands."#;

/// OpenAI-compatible LLM analyzer
pub struct OpenAiCompatibleAnalyzer {
    config: LlmConfig,
    client: reqwest::blocking::Client,
}

impl OpenAiCompatibleAnalyzer {
    /// Create a new analyzer with the given configuration
    pub fn new(config: LlmConfig) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());

        Self { config, client }
    }

    /// Analyze a file and return the LLM verdict
    pub fn analyze_file(
        &self,
        source: &str,
        file_path: &Path,
        findings: &[Finding],
    ) -> Result<LlmVerdict, LlmError> {
        // Truncate source if > 50,000 bytes
        let (source_to_send, truncation_notice) = if source.len() > 50_000 {
            // Find a valid UTF-8 boundary at ~50,000 bytes
            let truncation_point = source
                .char_indices()
                .take(50_000)
                .last()
                .map(|(i, _)| i)
                .unwrap_or(50_000);
            let truncated = &source[..truncation_point];
            (
                truncated,
                format!(
                    "\n// ... [truncated, original size: {} bytes]",
                    source.len()
                ),
            )
        } else {
            (source, String::new())
        };

        // Build findings JSON (simplified for LLM)
        let findings_json: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "rule_id": Self::finding_rule_id(f),
                    "severity": f.severity.as_str(),
                    "category": f.category.as_str(),
                    "line": f.line,
                    "message": f.description
                })
            })
            .collect();

        let findings_json_str = serde_json::to_string(&findings_json).unwrap_or_default();

        // Build user prompt
        let user_prompt = format!(
            r#"## File: {}

## Static analysis findings:
{}

## Source code:
```
{}{}
```"#,
            file_path.display(),
            findings_json_str,
            source_to_send,
            truncation_notice
        );

        // Build API request
        let request_body = serde_json::json!({
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.1
        });

        // Make API call
        let response = self
            .client
            .post(format!("{}/chat/completions", self.config.base_url))
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            return Err(LlmError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        let response_json: serde_json::Value = response.json()?;

        // Extract content from response
        let content = response_json
            .pointer("/choices/0/message/content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LlmError::ParseError {
                raw_content: response_json.to_string(),
                source: serde_json::from_str::<serde_json::Value>("").unwrap_err(),
            })?;

        // Parse the JSON response (strip markdown code fences if present)
        let json_str = Self::strip_markdown_fences(content);
        let verdict: LlmVerdict =
            serde_json::from_str(json_str).map_err(|e| LlmError::ParseError {
                raw_content: content.to_string(),
                source: e,
            })?;

        Ok(verdict)
    }

    /// Extract a rule_id from a Finding (simplified)
    fn finding_rule_id(finding: &Finding) -> String {
        // Map category to rule ID
        match finding.category.as_str() {
            "stegano_payload" => "GW001".to_string(),
            "decoder_function" => "GW002".to_string(),
            "invisible_character" => "GW003".to_string(),
            "bidirectional_override" => "GW004".to_string(),
            "encrypted_payload" => "GW005".to_string(),
            "hardcoded_key_decryption" => "GW006".to_string(),
            "rc4_pattern" => "GW007".to_string(),
            "header_c2" => "GW008".to_string(),
            other => format!("UNKNOWN_{}", other),
        }
    }

    /// Strip markdown code fences from a string
    fn strip_markdown_fences(content: &str) -> &str {
        let content = content.trim();
        if content.starts_with("```json") {
            if let Some(end) = content.rfind("```") {
                return content[7..end].trim();
            }
        } else if content.starts_with("```") {
            if let Some(end) = content.rfind("```") {
                return content[3..end].trim();
            }
        }
        content
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_markdown_fences_json() {
        let content = r#"```json
{"is_malicious": true}
```"#;
        let stripped = OpenAiCompatibleAnalyzer::strip_markdown_fences(content);
        assert_eq!(stripped, r#"{"is_malicious": true}"#);
    }

    #[test]
    fn test_strip_markdown_fences_plain() {
        let content = r#"{"is_malicious": true}"#;
        let stripped = OpenAiCompatibleAnalyzer::strip_markdown_fences(content);
        assert_eq!(stripped, r#"{"is_malicious": true}"#);
    }

    #[test]
    fn test_strip_markdown_fences_generic() {
        let content = r#"```
{"is_malicious": true}
```"#;
        let stripped = OpenAiCompatibleAnalyzer::strip_markdown_fences(content);
        assert_eq!(stripped, r#"{"is_malicious": true}"#);
    }

    #[test]
    fn test_config_from_env() {
        std::env::set_var("GLASSWARE_LLM_BASE_URL", "https://api.test.com/v1");
        std::env::set_var("GLASSWARE_LLM_API_KEY", "test-key");

        let config = LlmConfig::from_env().unwrap();
        assert_eq!(config.base_url, "https://api.test.com/v1");
        assert_eq!(config.api_key, "test-key");

        std::env::remove_var("GLASSWARE_LLM_BASE_URL");
        std::env::remove_var("GLASSWARE_LLM_API_KEY");
    }
}
