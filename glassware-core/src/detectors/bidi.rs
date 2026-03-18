//! Bidirectional Override Detector
//!
//! Detects bidirectional text overrides that can reverse displayed text.

use crate::config::UnicodeConfig;
use crate::finding::{DetectionCategory, Finding, Severity};
use crate::ranges::get_bidi_name;

/// Detector for bidirectional override attacks
pub struct BidiDetector {
    #[allow(dead_code)]
    config: UnicodeConfig,
}

impl BidiDetector {
    /// Create a new bidi detector
    pub fn new(config: UnicodeConfig) -> Self {
        Self { config }
    }

    /// Create with default config
    pub fn with_default_config() -> Self {
        Self::new(UnicodeConfig::default())
    }

    /// Scan content for bidirectional override attacks
    pub fn detect(&self, content: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            for (col_num, ch) in line.chars().enumerate() {
                let code_point = ch as u32;

                if let Some(bidi_name) = get_bidi_name(code_point) {
                    let severity = Self::determine_severity(code_point, bidi_name);

                    let finding = Finding::new(
                        file_path,
                        line_num + 1,
                        col_num + 1,
                        code_point,
                        ch,
                        DetectionCategory::BidirectionalOverride,
                        severity,
                        &Self::get_description(code_point, bidi_name),
                        &Self::get_remediation(code_point, bidi_name),
                    )
                    .with_cwe_id("CWE-172")
                    .with_reference("https://unicode.org/reports/tr36/")
                    .with_context(&Self::get_context(line, col_num));

                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Determine severity based on bidi character type
    fn determine_severity(_code_point: u32, bidi_name: &str) -> Severity {
        match bidi_name {
            "RLO" => Severity::Critical,
            "RLE" | "LRO" => Severity::High,
            "LRE" => Severity::Medium,
            "PDF" | "LRI" | "RLI" | "FSI" | "PDI" => Severity::Medium,
            "LRM" | "RLM" | "ALM" => Severity::Low,
            _ => Severity::Medium,
        }
    }

    /// Get human-readable description
    fn get_description(code_point: u32, bidi_name: &str) -> String {
        let danger_level = match bidi_name {
            "RLO" => " [MOST DANGEROUS - reverses text display]",
            "RLE" | "LRO" => " [HIGH RISK - can hide malicious content]",
            _ => "",
        };

        format!(
            "Bidirectional control character detected: {} (U+{:04X}){}",
            bidi_name, code_point, danger_level
        )
    }

    /// Get remediation guidance
    fn get_remediation(_code_point: u32, bidi_name: &str) -> String {
        match bidi_name {
            "RLO" => "IMMEDIATE ACTION: Remove this RLO character immediately. It reverses \
                     text display and is commonly used to hide malicious content. For example, \
                     'exe.txt' with RLO becomes 'txt.exe' when displayed. Review the actual \
                     byte sequence of the file using a hex editor."
                .to_string(),
            "RLE" | "LRO" => "Remove this bidirectional override character. These can be used \
                             to hide malicious content by reversing text display. Review the \
                             context to understand the true content."
                .to_string(),
            _ => "Remove the bidirectional control character unless there's a legitimate \
                  reason for it (e.g., proper RTL language support). Review the context \
                  to ensure it's not being used to hide content."
                .to_string(),
        }
    }

    /// Get context around the character position (Unicode-safe)
    fn get_context(line: &str, char_pos: usize) -> String {
        let chars: Vec<char> = line.chars().collect();
        let len = chars.len();
        let start = char_pos.saturating_sub(20);
        let end = (char_pos + 20).min(len);

        let prefix = if start > 0 { "..." } else { "" };
        let suffix = if end < len { "..." } else { "" };

        let context: String = chars[start..end].iter().collect();
        format!("{}{}{}", prefix, context, suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rlo_detection() {
        let detector = BidiDetector::with_default_config();

        let content = "const file = \"test\u{202E}exe\";";
        let findings = detector.detect(content, "test.js");

        assert!(!findings.is_empty());
        assert_eq!(findings[0].code_point, 0x202E);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_rle_detection() {
        let detector = BidiDetector::with_default_config();

        let content = "const text = \"hello\u{202B}world\";";
        let findings = detector.detect(content, "test.js");

        assert!(!findings.is_empty());
        assert_eq!(findings[0].code_point, 0x202B);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_clean_content() {
        let detector = BidiDetector::with_default_config();

        let content = "const normal = 'hello world';";
        let findings = detector.detect(content, "test.js");

        assert!(findings.is_empty());
    }
}
