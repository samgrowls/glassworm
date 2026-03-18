//! Unicode Tag Detector
//!
//! Detects Unicode tag characters that can be used for metadata injection.
//!
//! Unicode Range:
//! - U+E0000-U+E007F: Tags (language tags, etc.)

use crate::config::UnicodeConfig;
use crate::finding::{DetectionCategory, Finding, Severity};

/// Detector for Unicode tag attacks
pub struct UnicodeTagDetector {
    #[allow(dead_code)]
    config: UnicodeConfig,
}

impl UnicodeTagDetector {
    /// Create a new Unicode tag detector
    pub fn new(config: UnicodeConfig) -> Self {
        Self { config }
    }

    /// Create with default config
    pub fn with_default_config() -> Self {
        Self::new(UnicodeConfig::default())
    }

    /// Scan content for Unicode tag attacks
    pub fn detect(&self, content: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            for (col_num, ch) in line.chars().enumerate() {
                let code_point = ch as u32;

                // Check if this is in the tags range (U+E0000-U+E007F)
                if (0xE0000..=0xE007F).contains(&code_point) {
                    let tag_name = Self::get_tag_name(code_point);

                    let finding = Finding::new(
                        file_path,
                        line_num + 1,
                        col_num + 1,
                        code_point,
                        ch,
                        DetectionCategory::UnicodeTag,
                        Severity::Medium,
                        &format!(
                            "Unicode tag character detected: {} (U+{:04X})",
                            tag_name, code_point
                        ),
                        "Remove the Unicode tag character. These are rarely used in legitimate \
                         code and can be used to inject hidden metadata or bypass security checks. \
                         If this appears in a string literal, it may be an attempt to hide data.",
                    )
                    .with_cwe_id("CWE-172")
                    .with_context(&Self::get_context(line, col_num));

                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Get human-readable name for a tag character
    fn get_tag_name(code_point: u32) -> String {
        match code_point {
            0xE0001 => "Language Tag".to_string(),
            0xE007F => "Cancel Tag".to_string(),
            0xE0020..=0xE007E => {
                let ascii = (code_point - 0xE0000) as u8;
                if (0x20..=0x7E).contains(&ascii) {
                    format!("Tag: {}", ascii as char)
                } else {
                    format!("Tag (U+{:04X})", code_point)
                }
            }
            _ => format!("Tag (U+{:04X})", code_point),
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
    fn test_tag_detection() {
        let detector = UnicodeTagDetector::with_default_config();

        // Language tag character
        let content = "const x = \"test\u{E0001}value\";";
        let findings = detector.detect(content, "test.js");

        assert!(!findings.is_empty());
        assert_eq!(findings[0].code_point, 0xE0001);
        assert_eq!(findings[0].category, DetectionCategory::UnicodeTag);
    }

    #[test]
    fn test_clean_content() {
        let detector = UnicodeTagDetector::with_default_config();

        let content = "const normal = 'hello world';";
        let findings = detector.detect(content, "test.js");

        assert!(findings.is_empty());
    }
}
