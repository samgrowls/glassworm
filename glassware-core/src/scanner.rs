//! Unicode Scanner - Main Entry Point
//!
//! Primary entry point for Unicode attack detection.

use crate::config::UnicodeConfig;
use crate::detectors::{
    BidiDetector, GlasswareDetector, HomoglyphDetector, InvisibleCharDetector, UnicodeTagDetector,
};
use crate::finding::{Finding, Severity};

/// Primary entry point for Unicode attack detection
pub struct UnicodeScanner {
    config: UnicodeConfig,
    invisible_detector: InvisibleCharDetector,
    homoglyph_detector: HomoglyphDetector,
    bidi_detector: BidiDetector,
    glassware_detector: GlasswareDetector,
    tag_detector: UnicodeTagDetector,
}

impl UnicodeScanner {
    /// Create a new Unicode scanner with the given configuration
    pub fn new(config: UnicodeConfig) -> Self {
        Self {
            invisible_detector: InvisibleCharDetector::new(config.clone()),
            homoglyph_detector: HomoglyphDetector::new(config.clone()),
            bidi_detector: BidiDetector::new(config.clone()),
            glassware_detector: GlasswareDetector::new(config.clone()),
            tag_detector: UnicodeTagDetector::new(config.clone()),
            config,
        }
    }

    /// Create with default configuration
    pub fn with_default_config() -> Self {
        Self::new(UnicodeConfig::default())
    }

    /// Create for i18n projects (more permissive)
    pub fn for_i18n_project() -> Self {
        Self::new(UnicodeConfig::for_i18n_project())
    }

    /// Create for high-security projects (stricter)
    pub fn for_high_security() -> Self {
        Self::new(UnicodeConfig::for_high_security())
    }

    /// Scan content for all Unicode attacks
    pub fn scan(&self, content: &str, file_path: &str) -> Vec<Finding> {
        let mut all_findings = Vec::new();

        // Run all enabled detectors
        if self.config.detectors.invisible_chars {
            let findings = self.invisible_detector.detect(content, file_path);
            all_findings.extend(findings);
        }

        if self.config.detectors.homoglyphs {
            let findings = self.homoglyph_detector.detect(content, file_path);
            all_findings.extend(findings);
        }

        if self.config.detectors.bidirectional {
            let findings = self.bidi_detector.detect(content, file_path);
            all_findings.extend(findings);
        }

        if self.config.detectors.glassware {
            let findings = self.glassware_detector.detect(content, file_path);
            all_findings.extend(findings);
        }

        if self.config.detectors.unicode_tags {
            let findings = self.tag_detector.detect(content, file_path);
            all_findings.extend(findings);
        }

        // Sort findings by severity (critical first) and then by location
        all_findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| a.column.cmp(&b.column))
        });

        all_findings
    }

    /// Scan only for invisible characters
    pub fn scan_invisible(&self, content: &str, file_path: &str) -> Vec<Finding> {
        self.invisible_detector.detect(content, file_path)
    }

    /// Scan only for homoglyph attacks
    pub fn scan_homoglyphs(&self, content: &str, file_path: &str) -> Vec<Finding> {
        self.homoglyph_detector.detect(content, file_path)
    }

    /// Scan only for bidirectional overrides
    pub fn scan_bidi(&self, content: &str, file_path: &str) -> Vec<Finding> {
        self.bidi_detector.detect(content, file_path)
    }

    /// Scan only for Glassware patterns
    pub fn scan_glassware(&self, content: &str, file_path: &str) -> Vec<Finding> {
        self.glassware_detector.detect(content, file_path)
    }

    /// Scan only for Unicode tags
    pub fn scan_tags(&self, content: &str, file_path: &str) -> Vec<Finding> {
        self.tag_detector.detect(content, file_path)
    }

    /// Get the configuration
    pub fn get_config(&self) -> &UnicodeConfig {
        &self.config
    }

    /// List all available detectors
    pub fn list_detectors() -> Vec<&'static str> {
        vec![
            "invisible_char",
            "homoglyph",
            "bidi",
            "glassware",
            "unicode_tag",
        ]
    }

    /// Check if content contains any invisible characters (quick check)
    pub fn has_invisible_chars(content: &str) -> bool {
        content.chars().any(|ch| {
            let cp = ch as u32;
            (0xFE00..=0xFE0F).contains(&cp)
                || (0x200B..=0x200F).contains(&cp)
                || (0x202A..=0x202E).contains(&cp)
                || (0xE0000..=0xE007F).contains(&cp)
        })
    }

    /// Check if content contains any confusable characters (quick check)
    pub fn has_confusables(content: &str) -> bool {
        use crate::confusables::data::is_confusable;
        content.chars().any(is_confusable)
    }

    /// Deduplicate findings (same file, line, column, code_point)
    pub fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
        use std::collections::HashSet;

        let mut seen = HashSet::new();
        let mut deduped = Vec::new();

        for finding in findings {
            let key = (
                finding.file.clone(),
                finding.line,
                finding.column,
                finding.code_point,
            );

            if !seen.contains(&key) {
                seen.insert(key);
                deduped.push(finding);
            }
        }

        deduped
    }
}

/// Statistics for a Unicode scan session
#[derive(Debug, Clone, Default)]
pub struct ScanSessionStats {
    /// Total number of files scanned
    pub total_files: usize,
    /// Total number of findings across all files
    pub total_findings: usize,
    /// Number of critical severity findings
    pub critical_findings: usize,
    /// Number of high severity findings
    pub high_findings: usize,
    /// Number of medium severity findings
    pub medium_findings: usize,
    /// Number of low severity findings
    pub low_findings: usize,
    /// Total scan duration in milliseconds
    pub scan_duration_ms: u64,
}

impl ScanSessionStats {
    /// Create empty scan session stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Create stats from a list of findings and scan duration
    pub fn from_findings(findings: &[Finding], duration_ms: u64) -> Self {
        let mut stats = Self {
            total_files: findings
                .iter()
                .map(|f| &f.file)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            total_findings: findings.len(),
            scan_duration_ms: duration_ms,
            ..Default::default()
        };

        for finding in findings {
            match finding.severity {
                Severity::Critical => stats.critical_findings += 1,
                Severity::High => stats.high_findings += 1,
                Severity::Medium => stats.medium_findings += 1,
                Severity::Low => stats.low_findings += 1,
                Severity::Info => stats.low_findings += 1, // Count Info as Low for stats
            }
        }

        stats
    }
}

/// Simple function to scan content for Unicode attacks
///
/// This is the main entry point for simple use cases.
///
/// # Arguments
///
/// * `content` - The source code content to scan
/// * `filename` - The filename (used for reporting)
///
/// # Returns
///
/// A vector of Unicode findings
///
/// # Example
///
/// ```rust
/// use glassware_core::scan;
///
/// let content = "const secret\u{FE00}Key = 'value';";
/// let findings = scan(content, "test.js");
///
/// for finding in findings {
///     println!("Found: {}", finding.description);
/// }
/// ```
pub fn scan(content: &str, filename: &str) -> Vec<Finding> {
    let scanner = UnicodeScanner::with_default_config();
    scanner.scan(content, filename)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::DetectionCategory;

    #[test]
    fn test_scanner_creation() {
        let _scanner = UnicodeScanner::with_default_config();
        assert_eq!(UnicodeScanner::list_detectors().len(), 5);
    }

    #[test]
    fn test_full_scan_variation_selector() {
        let scanner = UnicodeScanner::with_default_config();

        let content = "const secret\u{FE00}Key = 'value';";
        let findings = scanner.scan(content, "test.js");

        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.category == DetectionCategory::InvisibleCharacter));
    }

    #[test]
    fn test_full_scan_homoglyph() {
        let scanner = UnicodeScanner::with_default_config();

        let content = "const pаssword = 'secret';";
        let findings = scanner.scan(content, "test.js");

        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.category == DetectionCategory::Homoglyph));
    }

    #[test]
    fn test_full_scan_bidi() {
        let scanner = UnicodeScanner::with_default_config();

        let content = "const file = \"test\u{202E}exe\";";
        let findings = scanner.scan(content, "test.js");

        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.category == DetectionCategory::BidirectionalOverride));
    }

    #[test]
    fn test_clean_content() {
        let scanner = UnicodeScanner::with_default_config();

        let content = "const normal = 'hello world';";
        let findings = scanner.scan(content, "test.js");

        assert!(findings.is_empty());
    }

    #[test]
    fn test_has_invisible_chars() {
        assert!(UnicodeScanner::has_invisible_chars("hello\u{FE00}world"));
        assert!(UnicodeScanner::has_invisible_chars("test\u{200B}"));
        assert!(!UnicodeScanner::has_invisible_chars("normal text"));
    }

    #[test]
    fn test_has_confusables() {
        assert!(UnicodeScanner::has_confusables("pаssword"));
        assert!(!UnicodeScanner::has_confusables("password"));
    }

    #[test]
    fn test_deduplication() {
        let finding1 = Finding::new(
            "test.js",
            1,
            5,
            0xFE00,
            '\u{FE00}',
            DetectionCategory::InvisibleCharacter,
            Severity::Critical,
            "test",
            "fix",
        );
        let finding2 = finding1.clone();
        let finding3 = Finding::new(
            "test.js",
            2,
            10,
            0xFE01,
            '\u{FE01}',
            DetectionCategory::InvisibleCharacter,
            Severity::Critical,
            "test",
            "fix",
        );

        let findings = vec![finding1.clone(), finding2, finding3];
        let deduped = UnicodeScanner::deduplicate_findings(findings);

        assert_eq!(deduped.len(), 2);
    }
}
