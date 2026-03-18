//! Invisible Character Detector
//!
//! Detects invisible Unicode characters used in Glassware-style attacks.
//!
//! Unicode Ranges Monitored:
//! - U+FE00-U+FE0F: Variation Selectors (Glassware primary)
//! - U+E0100-U+E01EF: Variation Selectors Supplement
//! - U+200B-U+200F: Zero-width space, joiner, non-joiner
//! - U+2060-U+206F: Word joiner, invisible operators
//! - U+E0000-U+E007F: Tags

use crate::config::UnicodeConfig;
use crate::finding::{DetectionCategory, Finding, Severity};
use crate::ranges::{
    get_bidi_name, get_zero_width_name, is_in_critical_range, is_in_invisible_range,
    is_variation_selector,
};

/// Detector for invisible characters
pub struct InvisibleCharDetector {
    #[allow(dead_code)]
    config: UnicodeConfig,
}

impl InvisibleCharDetector {
    /// Create a new invisible character detector
    pub fn new(config: UnicodeConfig) -> Self {
        Self { config }
    }

    /// Create with default config
    pub fn with_default_config() -> Self {
        Self::new(UnicodeConfig::default())
    }

    /// Scan content for invisible characters
    pub fn detect(&self, content: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            for (col_num, ch) in line.chars().enumerate() {
                let code_point = ch as u32;

                if is_in_invisible_range(code_point) {
                    // Check if this is in a legitimate emoji context
                    if self.is_emoji_context(line, col_num) {
                        continue;
                    }

                    // Determine severity based on range
                    let severity = self.determine_severity(code_point);

                    let finding = Finding::new(
                        file_path,
                        line_num + 1,
                        col_num + 1,
                        code_point,
                        ch,
                        DetectionCategory::InvisibleCharacter,
                        severity,
                        &self.get_description(code_point),
                        &self.get_remediation(code_point),
                    )
                    .with_cwe_id("CWE-172")
                    .with_reference("https://www.aikido.dev/blog/glassware-returns-unicode-attack-github-npm-vscode")
                    .with_context(&self.get_context(line, col_num));

                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Check if the character at position is in an emoji context (legitimate)
    fn is_emoji_context(&self, line: &str, char_pos: usize) -> bool {
        let chars: Vec<char> = line.chars().collect();

        // Check if preceded by emoji character
        if char_pos > 0 {
            let prev = chars[char_pos - 1];
            let prev_cp = prev as u32;
            // Emoji ranges (simplified)
            if (0x1F300..=0x1F9FF).contains(&prev_cp)
                || (0x2600..=0x26FF).contains(&prev_cp)
                || (0x2700..=0x27BF).contains(&prev_cp)
            {
                return true;
            }
        }

        // Check if followed by emoji
        if char_pos < chars.len() - 1 {
            let next = chars[char_pos + 1];
            let next_cp = next as u32;
            if (0x1F300..=0x1F9FF).contains(&next_cp)
                || (0x2600..=0x26FF).contains(&next_cp)
                || (0x2700..=0x27BF).contains(&next_cp)
            {
                return true;
            }
        }

        false
    }

    /// Determine severity based on code point
    fn determine_severity(&self, code_point: u32) -> Severity {
        if is_in_critical_range(code_point) {
            return Severity::Critical;
        }

        if is_variation_selector(code_point) {
            return Severity::Critical;
        }

        if get_bidi_name(code_point).is_some() {
            return Severity::High;
        }

        if get_zero_width_name(code_point).is_some() {
            return Severity::High;
        }

        Severity::Medium
    }

    /// Get human-readable description
    fn get_description(&self, code_point: u32) -> String {
        if let Some(name) = get_bidi_name(code_point) {
            return format!(
                "Bidirectional control character detected: {} (U+{:04X})",
                name, code_point
            );
        }

        if let Some(name) = get_zero_width_name(code_point) {
            return format!(
                "Zero-width character detected: {} (U+{:04X})",
                name, code_point
            );
        }

        if is_variation_selector(code_point) {
            return format!(
                "Variation selector detected (U+{:04X}) - commonly used in Glassware attacks",
                code_point
            );
        }

        format!(
            "Invisible Unicode character detected (U+{:04X})",
            code_point
        )
    }

    /// Get remediation guidance
    fn get_remediation(&self, code_point: u32) -> String {
        if is_variation_selector(code_point) {
            return "Remove the variation selector. If this is intentional (e.g., emoji skin tone), \
                    verify the character is not being used to hide malicious content. \
                    Review the surrounding code for decoder patterns."
                .to_string();
        }

        if get_bidi_name(code_point).is_some() {
            return "Remove the bidirectional control character. These are commonly used to \
                    reverse text display and hide malicious content. Review the actual byte \
                    sequence of the file to understand the true content."
                .to_string();
        }

        if get_zero_width_name(code_point).is_some() {
            return "Remove the zero-width character. These characters are invisible but can \
                    be used to inject hidden content or bypass security checks."
                .to_string();
        }

        "Remove the invisible character. Verify if this is intentional (e.g., for i18n) \
         or if it's being used to hide malicious content."
            .to_string()
    }

    /// Get context around the character position (Unicode-safe)
    fn get_context(&self, line: &str, char_pos: usize) -> String {
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
    fn test_variation_selector_detection() {
        let detector = InvisibleCharDetector::with_default_config();

        let content = "const secret\u{FE00}Key = 'value';";
        let findings = detector.detect(content, "test.js");

        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, DetectionCategory::InvisibleCharacter);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].code_point, 0xFE00);
    }

    #[test]
    fn test_zero_width_space_detection() {
        let detector = InvisibleCharDetector::with_default_config();

        let content = "const pass\u{200B}word = 'secret';";
        let findings = detector.detect(content, "test.js");

        assert!(!findings.is_empty());
        assert_eq!(findings[0].code_point, 0x200B);
    }

    #[test]
    fn test_rlo_detection() {
        let detector = InvisibleCharDetector::with_default_config();

        let content = "const file = \"test\u{202E}txt\";";
        let findings = detector.detect(content, "test.js");

        assert!(!findings.is_empty());
        assert_eq!(findings[0].code_point, 0x202E);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_clean_content() {
        let detector = InvisibleCharDetector::with_default_config();

        let content = "const normal = 'hello world';";
        let findings = detector.detect(content, "test.js");

        assert!(findings.is_empty());
    }
}
