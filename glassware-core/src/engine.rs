//! Scan Engine
//!
//! Orchestrates multiple detectors over files, merging and sorting findings.

use crate::config::UnicodeConfig;
use crate::detector::Detector;
#[cfg(feature = "semantic")]
use crate::detector::SemanticDetector;
use crate::encrypted_payload_detector::EncryptedPayloadDetector;
use crate::finding::Finding;
use crate::header_c2_detector::HeaderC2Detector;
use crate::unicode_detector::UnicodeDetector;
#[cfg(feature = "llm")]
use std::collections::HashMap;
use std::path::Path;

/// Result of a scan operation, including findings and optional LLM verdicts.
pub struct ScanResult {
    pub findings: Vec<Finding>,
    #[cfg(feature = "llm")]
    pub llm_verdicts: Vec<crate::llm::LlmFileResult>,
}

/// Orchestrates multiple detectors over files.
///
/// The ScanEngine registers detectors and runs them against file content,
/// collecting and sorting all findings.
pub struct ScanEngine {
    detectors: Vec<Box<dyn Detector>>,
    #[cfg(feature = "semantic")]
    semantic_detectors: Vec<Box<dyn SemanticDetector>>,
    config: UnicodeConfig,
    #[cfg(feature = "llm")]
    use_llm: bool,
}

impl ScanEngine {
    /// Create a new engine with no detectors.
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
            #[cfg(feature = "semantic")]
            semantic_detectors: Vec::new(),
            config: UnicodeConfig::default(),
            #[cfg(feature = "llm")]
            use_llm: false,
        }
    }

    /// Enable or disable LLM analysis
    #[cfg(feature = "llm")]
    pub fn with_llm(mut self, use_llm: bool) -> Self {
        self.use_llm = use_llm;
        self
    }

    /// Create an engine pre-loaded with all built-in detectors.
    pub fn default_detectors() -> Self {
        let mut engine = Self::new();
        engine.register(Box::new(UnicodeDetector::new()));
        engine.register(Box::new(EncryptedPayloadDetector::new()));
        engine.register(Box::new(HeaderC2Detector::new()));

        #[cfg(feature = "semantic")]
        {
            engine.register_semantic(Box::new(crate::gw005_semantic::Gw005SemanticDetector::new()));
            engine.register_semantic(Box::new(crate::gw006_semantic::Gw006SemanticDetector::new()));
            engine.register_semantic(Box::new(crate::gw007_semantic::Gw007SemanticDetector::new()));
            engine.register_semantic(Box::new(crate::gw008_semantic::Gw008SemanticDetector::new()));
        }

        engine
    }

    /// Create an engine with a custom configuration.
    pub fn with_config(config: UnicodeConfig) -> Self {
        Self {
            detectors: Vec::new(),
            #[cfg(feature = "semantic")]
            semantic_detectors: Vec::new(),
            config,
            #[cfg(feature = "llm")]
            use_llm: false,
        }
    }

    /// Register a detector.
    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    /// Register a semantic detector.
    #[cfg(feature = "semantic")]
    pub fn register_semantic(&mut self, detector: Box<dyn SemanticDetector>) {
        self.semantic_detectors.push(detector);
    }

    /// Scan file content with all registered detectors.
    /// Returns findings sorted by location.
    ///
    /// For LLM analysis, use `scan_with_llm()` instead.
    pub fn scan(&self, path: &Path, content: &str) -> Vec<Finding> {
        self.scan_internal(path, content).findings
    }

    /// Scan file content with all registered detectors and optional LLM analysis.
    #[cfg(feature = "llm")]
    pub fn scan_with_llm(&self, path: &Path, content: &str) -> ScanResult {
        self.scan_internal(path, content)
    }

    /// Internal scan method that returns ScanResult
    fn scan_internal(&self, path: &Path, content: &str) -> ScanResult {
        let mut findings: Vec<Finding> = Vec::new();

        // Run regex-based detectors on all files
        for detector in &self.detectors {
            findings.extend(detector.scan(path, content, &self.config));
        }

        // Run semantic detectors on JS/TS files only
        #[cfg(feature = "semantic")]
        if !self.semantic_detectors.is_empty() {
            if let Some(analysis) = crate::semantic::build_semantic(content, path) {
                let sources = crate::taint::find_sources(&analysis);
                let sinks = crate::taint::find_sinks(&analysis);
                let flows = crate::taint::check_flows(&analysis, &sources, &sinks);

                for detector in &self.semantic_detectors {
                    findings
                        .extend(detector.detect_semantic(content, path, &flows, &sources, &sinks));
                }
            }
        }

        // Sort by line, then column
        findings.sort_by(|a, b| a.line.cmp(&b.line).then(a.column.cmp(&b.column)));

        // Run LLM analysis if enabled and there are findings
        #[cfg(feature = "llm")]
        let llm_verdicts = if self.use_llm && !findings.is_empty() {
            self.run_llm_analysis(&findings, path, content)
        } else {
            Vec::new()
        };

        ScanResult {
            findings,
            #[cfg(feature = "llm")]
            llm_verdicts,
        }
    }

    /// Run LLM analysis on flagged files
    #[cfg(feature = "llm")]
    fn run_llm_analysis(
        &self,
        findings: &[Finding],
        _path: &Path,
        content: &str,
    ) -> Vec<crate::llm::LlmFileResult> {
        use crate::llm::{LlmConfig, OpenAiCompatibleAnalyzer};

        // Try to load config - if it fails, return empty vec (don't fail the scan)
        let config = match LlmConfig::from_env() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Warning: LLM analysis skipped - {}", e);
                return Vec::new();
            }
        };

        let analyzer = OpenAiCompatibleAnalyzer::new(config);

        // Group findings by file
        let mut findings_by_file: HashMap<std::path::PathBuf, Vec<&Finding>> = HashMap::new();
        for finding in findings {
            findings_by_file
                .entry(std::path::PathBuf::from(&finding.file))
                .or_default()
                .push(finding);
        }

        let mut results = Vec::new();

        // Analyze each file
        for (file_path, file_findings) in findings_by_file {
            // Convert Vec<&Finding> to Vec<Finding> for analyze_file
            let findings_vec: Vec<Finding> = file_findings.iter().map(|f| (*f).clone()).collect();
            match analyzer.analyze_file(content, &file_path, &findings_vec) {
                Ok(verdict) => {
                    results.push(crate::llm::LlmFileResult { file_path, verdict });
                }
                Err(e) => {
                    eprintln!("Warning: LLM analysis failed for {:?}: {}", file_path, e);
                }
            }
        }

        results
    }

    /// Get the number of registered detectors.
    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::DetectionCategory;
    use crate::scanner::UnicodeScanner;

    #[test]
    fn test_engine_default_detectors() {
        let engine = ScanEngine::default_detectors();
        assert_eq!(engine.detector_count(), 3);
    }

    #[test]
    fn test_engine_scan_variation_selector() {
        let engine = ScanEngine::default_detectors();
        let content = "const secret\u{FE00}Key = 'value';";
        let findings = engine.scan(Path::new("test.js"), content);

        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.category == DetectionCategory::InvisibleCharacter));
    }

    #[test]
    fn test_engine_matches_unicode_scanner() {
        // Verify that ScanEngine produces the same results as UnicodeScanner
        let engine = ScanEngine::default_detectors();
        let scanner = UnicodeScanner::with_default_config();

        let content = "const secret\u{FE00}Key = 'value';";
        let engine_findings = engine.scan(Path::new("test.js"), content);
        let scanner_findings = scanner.scan(content, "test.js");

        // Both should find the same number of findings
        assert_eq!(engine_findings.len(), scanner_findings.len());

        // Both should find an InvisibleCharacter
        assert!(engine_findings
            .iter()
            .any(|f| f.category == DetectionCategory::InvisibleCharacter));
        assert!(scanner_findings
            .iter()
            .any(|f| f.category == DetectionCategory::InvisibleCharacter));
    }
}
