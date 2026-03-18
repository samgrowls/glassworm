//! Homoglyph Detector
//!
//! Detects confusable characters that could be used for spoofing attacks.

use crate::config::UnicodeConfig;
use crate::confusables::data::{
    get_base_char, get_confusable_script, get_similarity, is_confusable,
};
use crate::finding::{DetectionCategory, Finding, Severity};
use crate::script_detector::{
    extract_identifiers, find_identifier_at_position, has_mixed_scripts, is_pure_non_latin,
};

/// Detector for homoglyph attacks
pub struct HomoglyphDetector {
    #[allow(dead_code)]
    min_confidence: f32,
    #[allow(dead_code)]
    config: UnicodeConfig,
}

impl HomoglyphDetector {
    /// Create a new homoglyph detector
    pub fn new(config: UnicodeConfig) -> Self {
        Self {
            min_confidence: 0.8,
            config,
        }
    }

    /// Create with default config
    pub fn with_default_config() -> Self {
        Self::new(UnicodeConfig::default())
    }

    /// Scan content for homoglyph attacks
    pub fn detect(&self, content: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            // Skip comment lines entirely
            let trimmed = line.trim();
            if trimmed.starts_with("//")
                || trimmed.starts_with("#")
                || trimmed.starts_with("/*")
                || trimmed.starts_with("*")
                || trimmed.starts_with("<!--")
            {
                continue;
            }

            // Extract identifiers from the line for context-aware detection
            let identifiers = extract_identifiers(line);

            for (col_num, ch) in line.chars().enumerate() {
                if is_confusable(ch) {
                    // Find which identifier contains this character
                    let identifier = find_identifier_at_position(line, col_num, &identifiers);

                    if let Some(id) = identifier {
                        let id_ref = id.as_str();

                        // SKIP pure non-Latin (legitimate i18n like Greek μήνυμα, Cyrillic сообщение)
                        if is_pure_non_latin(id_ref) {
                            continue;
                        }

                        // Only flag if identifier has mixed scripts (deceptive attack)
                        if !has_mixed_scripts(id_ref) {
                            continue;
                        }

                        // FLAG: Mixed script identifier (the actual attack)
                        let code_point = ch as u32;
                        let severity = self.determine_severity(ch);

                        let finding = Finding::new(
                            file_path,
                            line_num + 1,
                            col_num + 1,
                            code_point,
                            ch,
                            DetectionCategory::Homoglyph,
                            severity,
                            &self.get_description_for_identifier(ch, id_ref),
                            &self.get_remediation_for_identifier(ch, id_ref),
                        )
                        .with_cwe_id("CWE-172")
                        .with_reference("https://docs.github.com/en/security")
                        .with_context(id_ref);

                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }

    /// Determine severity based on character similarity
    fn determine_severity(&self, ch: char) -> Severity {
        let similarity = get_similarity(ch).unwrap_or(0.5);

        if similarity >= 0.99 {
            Severity::Critical
        } else if similarity >= 0.95 {
            Severity::High
        } else if similarity >= 0.9 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    /// Get description for identifier-based detection
    fn get_description_for_identifier(&self, ch: char, identifier: &str) -> String {
        let script = get_confusable_script(ch).unwrap_or("Unknown");
        let base = get_base_char(ch).unwrap_or(ch);

        format!(
            "Mixed script identifier: '{}' contains '{}' (U+{:04X}) from {} script confusable with '{}'",
            identifier, ch, ch as u32, script, base
        )
    }

    /// Get remediation for identifier-based detection
    fn get_remediation_for_identifier(&self, ch: char, identifier: &str) -> String {
        let script = get_confusable_script(ch).unwrap_or("Unknown");
        let base = get_base_char(ch).unwrap_or(ch);

        format!(
            "Use pure Latin or pure non-Latin identifiers, not mixed scripts. \
             Replace '{}' with a consistent script. The character '{}' ({} script) \
             appears to be intentionally mixed with Latin characters to create a deceptive identifier. \
             Consider using '{}' instead.",
            identifier, ch, script, base
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cyrillic_a_detection() {
        let detector = HomoglyphDetector::with_default_config();

        // Cyrillic 'а' (U+0430) vs Latin 'a'
        let content = "const pаssword = 'secret';";
        let findings = detector.detect(content, "test.js");

        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, DetectionCategory::Homoglyph);
        assert_eq!(findings[0].code_point, 0x0430);
    }

    #[test]
    fn test_greek_o_detection() {
        let detector = HomoglyphDetector::with_default_config();

        // Greek 'ο' (U+03BF) vs Latin 'o'
        let content = "const lοgin = 'user';";
        let findings = detector.detect(content, "test.js");

        assert!(!findings.is_empty());
        assert_eq!(findings[0].code_point, 0x03BF);
    }

    #[test]
    fn test_clean_content() {
        let detector = HomoglyphDetector::with_default_config();

        let content = "const password = 'secret';";
        let findings = detector.detect(content, "test.js");

        assert!(findings.is_empty());
    }

    #[test]
    fn test_pure_cyrillic_allowed() {
        let detector = HomoglyphDetector::with_default_config();

        // Pure Cyrillic - should be allowed
        let content = "let сообщение = 'test';";
        let findings = detector.detect(content, "test.js");

        assert!(findings.is_empty());
    }
}
