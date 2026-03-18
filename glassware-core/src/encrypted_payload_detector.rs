//! Encrypted Payload Detector (GW005)
//!
//! Detects files containing BOTH a high-entropy encoded blob AND dynamic code
//! execution — the signature pattern of an encrypted loader.
//!
//! ## Detection Logic
//!
//! This detector emits a finding ONLY when BOTH conditions are present in the same file:
//!
//! 1. **High-entropy blob**: String/template literals longer than 64 characters with
//!    Shannon entropy > 4.5 bits/byte, or continuous hex/base64 blocks.
//! 2. **Dynamic execution**: `eval(`, `new Function(`, `vm.runInNewContext`, etc.
//!
//! ## Severity
//!
//! High — indicates potential encrypted payload loader.

use crate::config::UnicodeConfig;
use crate::detector::Detector;
use crate::finding::{DetectionCategory, Finding, Severity};
use std::path::Path;

/// Minimum length for high-entropy blob detection
const MIN_BLOB_LENGTH: usize = 64;

/// Entropy threshold for detecting encrypted/encoded content
const ENTROPY_THRESHOLD: f64 = 4.5;

/// Detector for encrypted payload patterns (GW005)
pub struct EncryptedPayloadDetector;

impl EncryptedPayloadDetector {
    /// Create a new encrypted payload detector
    pub fn new() -> Self {
        Self
    }
}

impl Default for EncryptedPayloadDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EncryptedPayloadDetector {
    fn name(&self) -> &str {
        "encrypted_payload"
    }

    fn scan(&self, path: &Path, content: &str, _config: &UnicodeConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for high-entropy blobs
        let has_high_entropy_blob = self.detect_high_entropy_blob(content);

        // Check for dynamic execution patterns
        let dynamic_exec_lines = self.find_dynamic_execution(content);

        // Only emit finding if BOTH conditions are present
        if has_high_entropy_blob && !dynamic_exec_lines.is_empty() {
            // Find the line with the high-entropy blob for the finding location
            let blob_line = self.find_high_entropy_blob_line(content).unwrap_or(1);

            let finding = Finding::new(
                &path.to_string_lossy(),
                blob_line,
                1,
                0,
                '\0',
                DetectionCategory::EncryptedPayload,
                Severity::High,
                "High-entropy blob combined with dynamic code execution — potential encrypted payload loader",
                "Review this file for encrypted payload patterns. The combination of high-entropy \
                 encoded data and dynamic code execution is characteristic of encrypted loaders \
                 used in supply chain attacks. Decode the blob to understand the hidden payload.",
            )
            .with_cwe_id("CWE-506")
            .with_reference("https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode");

            findings.push(finding);
        }

        findings
    }
}

impl EncryptedPayloadDetector {
    /// Check if content contains a high-entropy blob
    fn detect_high_entropy_blob(&self, content: &str) -> bool {
        // Check for hex patterns: continuous hex chars >= 64
        let hex_pattern = regex::Regex::new(r"[0-9a-fA-F]{64,}").unwrap();
        for m in hex_pattern.find_iter(content) {
            let entropy = self.calculate_entropy(m.as_str().as_bytes());
            if entropy > ENTROPY_THRESHOLD {
                return true;
            }
        }

        // Check for base64 patterns: continuous base64 chars >= 64
        let base64_pattern = regex::Regex::new(r"[A-Za-z0-9+/=]{64,}").unwrap();
        for m in base64_pattern.find_iter(content) {
            let entropy = self.calculate_entropy(m.as_str().as_bytes());
            if entropy > ENTROPY_THRESHOLD {
                return true;
            }
        }

        // Check string literals for high entropy
        for line in content.lines() {
            if let Some(literal) = self.extract_string_literal(line) {
                if literal.len() >= MIN_BLOB_LENGTH {
                    let entropy = self.calculate_entropy(literal.as_bytes());
                    if entropy > ENTROPY_THRESHOLD {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Find the line number containing a high-entropy blob
    fn find_high_entropy_blob_line(&self, content: &str) -> Option<usize> {
        // Check for hex patterns
        let hex_pattern = regex::Regex::new(r"[0-9a-fA-F]{64,}").unwrap();
        for (line_num, line) in content.lines().enumerate() {
            if hex_pattern.is_match(line) {
                return Some(line_num + 1);
            }
        }

        // Check for base64 patterns
        let base64_pattern = regex::Regex::new(r"[A-Za-z0-9+/=]{64,}").unwrap();
        for (line_num, line) in content.lines().enumerate() {
            if base64_pattern.is_match(line) {
                return Some(line_num + 1);
            }
        }

        // Check string literals
        for (line_num, line) in content.lines().enumerate() {
            if let Some(literal) = self.extract_string_literal(line) {
                if literal.len() >= MIN_BLOB_LENGTH {
                    let entropy = self.calculate_entropy(literal.as_bytes());
                    if entropy > ENTROPY_THRESHOLD {
                        return Some(line_num + 1);
                    }
                }
            }
        }

        None
    }

    /// Find lines containing dynamic execution patterns
    fn find_dynamic_execution(&self, content: &str) -> Vec<usize> {
        let mut exec_lines = Vec::new();

        let patterns = [
            r"\beval\s*\(",
            r"\bnew\s+Function\s*\(",
            r"\bvm\.runInNewContext\s*\(",
            r"\bvm\.runInThisContext\s*\(",
            r"\bchild_process\s*\+",
            r"\bexec\s*\(",
            r"\bexecSync\s*\(",
        ];

        for (line_num, line) in content.lines().enumerate() {
            for pattern in &patterns {
                let re = regex::Regex::new(pattern).unwrap();
                if re.is_match(line) {
                    exec_lines.push(line_num + 1);
                    break;
                }
            }
        }

        exec_lines
    }

    /// Extract a string literal from a line of code
    fn extract_string_literal(&self, line: &str) -> Option<String> {
        // Match single-quoted, double-quoted, or template literals
        let patterns = [
            regex::Regex::new(r#"["']([^"']{64,})["']"#).unwrap(),
            regex::Regex::new(r"`([^`]{64,})`").unwrap(),
        ];

        for pattern in &patterns {
            if let Some(caps) = pattern.captures(line) {
                if let Some(m) = caps.get(1) {
                    return Some(m.as_str().to_string());
                }
            }
        }

        None
    }

    /// Calculate Shannon entropy of byte data
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u64; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_base64_with_eval() {
        let detector = EncryptedPayloadDetector::new();
        let content = r#"
            const payload = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IHN0cmluZyB0aGF0IGlzIGxvbmcgZW5vdWdoIHRvIHRyaWdnZXIgZGV0ZWN0aW9uIGJhc2U2NCBlbmNvZGVkIGRhdGE=";
            eval(atob(payload));
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, DetectionCategory::EncryptedPayload);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_detect_hex_with_function() {
        let detector = EncryptedPayloadDetector::new();
        // High-entropy base64 string (encrypted-looking data)
        let content = r#"
            const data = "kJfXyZ2BvMnR0cHV3eIGIqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/";
            new Function(data)();
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, DetectionCategory::EncryptedPayload);
    }

    #[test]
    fn test_no_detect_eval_only() {
        let detector = EncryptedPayloadDetector::new();
        let content = r#"
            const x = "hello";
            eval(x);
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_detect_blob_only() {
        let detector = EncryptedPayloadDetector::new();
        let content = r#"
            const data = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IHN0cmluZyB0aGF0IGlzIGxvbmcgZW5vdWdoIHRvIHRyaWdnZXIgZGV0ZWN0aW9uIGJhc2U2NCBlbmNvZGVkIGRhdGE=";
            console.log(data);
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_detect_low_entropy() {
        let detector = EncryptedPayloadDetector::new();
        let content = r#"
            const repeated = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            eval(repeated);
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_detect_normal_code() {
        let detector = EncryptedPayloadDetector::new();
        let content = r#"
            const message = "Hello, World!";
            console.log(message);
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detect_vm_execution() {
        let detector = EncryptedPayloadDetector::new();
        let content = r#"
            const code = "dGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHN0cmluZyB0aGF0IGlzIGxvbmcgZW5vdWdoIHRvIHRyaWdnZXIgZGV0ZWN0aW9uIGFuZCBzaG91bGQgYmUgZmxhZ2dlZA==";
            vm.runInNewContext(code);
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detect_exec_sync() {
        let detector = EncryptedPayloadDetector::new();
        let content = r#"
            const cmd = "Y21kLmV4ZSAvYyBlY2hvIGhlbGxvIHdvcmxkIHRoaXMgaXMgYSBsb25nIGJhc2U2NCBlbmNvZGVkIHN0cmluZyBmb3IgdGVzdGluZyBwdXJwb3Nlcw==";
            execSync(cmd);
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detect_eval_atob_pattern() {
        let detector = EncryptedPayloadDetector::new();
        let content = r#"
            const data = "VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHBheWxvYWQgdGhhdCBpcyBsb25nIGVub3VnaCB0byB0cmlnZ2VyIGRldGVjdGlvbi4=";
            eval(atob(data));
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, DetectionCategory::EncryptedPayload);
    }

    #[test]
    fn test_detect_buffer_from_tostring_eval() {
        let detector = EncryptedPayloadDetector::new();
        let content = r#"
            const payload = "VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHBheWxvYWQgdGhhdCBpcyBsb25nIGVub3VnaCB0byB0cmlnZ2VyIGRldGVjdGlvbi4=";
            eval(Buffer.from(payload, 'base64').toString('utf-8'));
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_no_detect_low_entropy_blob_with_exec() {
        let detector = EncryptedPayloadDetector::new();
        let content = r#"
            const repeated = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            eval(repeated);
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        // Should NOT detect - low entropy blob
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_detect_short_blob_with_exec() {
        let detector = EncryptedPayloadDetector::new();
        let content = r#"
            const short = "SGVsbG8gV29ybGQh";
            eval(atob(short));
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        // Should NOT detect - blob too short (< 64 chars)
        assert!(findings.is_empty());
    }

    #[test]
    fn test_entropy_calculation_uniform() {
        let detector = EncryptedPayloadDetector::new();
        let entropy = detector.calculate_entropy(&[0x41, 0x41, 0x41, 0x41]);
        assert!((entropy - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_entropy_calculation_high() {
        let detector = EncryptedPayloadDetector::new();
        let data: Vec<u8> = (0..=255).collect();
        let entropy = detector.calculate_entropy(&data);
        assert!(entropy > 7.9);
    }
}
