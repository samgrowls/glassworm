//! Unicode Detector
//!
//! Wraps the existing Unicode scanning logic to implement the Detector trait.

use crate::config::UnicodeConfig;
use crate::detector::Detector;
use crate::finding::Finding;
use crate::scanner::UnicodeScanner;
use std::path::Path;

/// Unicode attack detector implementing the Detector trait.
///
/// This detector wraps the existing Unicode scanning logic including:
/// - Invisible character detection (zero-width, variation selectors)
/// - Homoglyph/confusable character detection
/// - Bidirectional override detection
/// - Glassware pattern detection
/// - Unicode tag detection
pub struct UnicodeDetector;

impl Detector for UnicodeDetector {
    fn name(&self) -> &str {
        "unicode"
    }

    fn scan(&self, path: &Path, content: &str, config: &UnicodeConfig) -> Vec<Finding> {
        // Use the existing UnicodeScanner to perform the scan
        let scanner = UnicodeScanner::new(config.clone());
        let file_path = path.to_string_lossy().to_string();
        scanner.scan(content, &file_path)
    }
}

impl Default for UnicodeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UnicodeDetector {
    /// Create a new Unicode detector
    pub fn new() -> Self {
        Self
    }
}
