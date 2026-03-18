//! Glassware Core - Attack Detection Library
//!
//! A zero-dependency library for detecting invisible Unicode characters and
//! trojan source attacks in source code.
//!
//! ## Features
//!
//! - **Invisible Character Detection**: Zero-width characters, variation selectors,
//!   bidi overrides used in Glassware-style attacks
//! - **Homoglyph Detection**: Confusable characters from Cyrillic, Greek scripts
//! - **Bidirectional Override Detection**: Bidi control characters that reverse text
//! - **Glassware Pattern Detection**: Decoder patterns, eval usage, encoding functions
//! - **Unicode Tag Detection**: Tag characters for metadata injection
//!
//! ## Example Usage
//!
//! ```rust
//! use glassware_core::{scan, Finding};
//!
//! // Scan content for Unicode attacks
//! let content = "const secret\u{FE00}Key = 'value';";
//! let findings = scan(content, "test.js");
//!
//! // Process findings
//! for finding in findings {
//!     println!("Found: {} at {}:{}", finding.description, finding.line, finding.column);
//! }
//! ```
//!
//! ## Performance
//!
//! - Time complexity: O(n) where n = number of characters
//! - Space complexity: O(1) beyond input storage
//! - Confusables lookup: O(1) using HashMap

pub mod classify;
pub mod config;
pub mod confusables;
pub mod decoder;
pub mod detector;
pub mod detectors;
pub mod encrypted_payload_detector;
pub mod engine;
pub mod finding;
#[cfg(feature = "semantic")]
pub mod gw005_semantic;
#[cfg(feature = "semantic")]
pub mod gw006_semantic;
#[cfg(feature = "semantic")]
pub mod gw007_semantic;
#[cfg(feature = "semantic")]
pub mod gw008_semantic;
pub mod header_c2_detector;
#[cfg(feature = "llm")]
pub mod llm;
pub mod ranges;
pub mod scanner;
pub mod script_detector;
#[cfg(feature = "semantic")]
pub mod semantic;
#[cfg(feature = "semantic")]
pub mod taint;
pub mod unicode_detector;

// Re-export main types for convenience
pub use classify::{
    get_bidi_name, get_zero_width_name, is_in_critical_range, is_in_invisible_range,
    is_variation_selector, BidiChar, InvisibleRange, ZeroWidthChar,
};

pub use config::{DetectorConfig, SensitivityLevel, UnicodeConfig};

pub use confusables::data::{
    get_base_char, get_confusable_script, get_similarity, is_confusable, ConfusableEntry,
};

pub use decoder::{
    count_vs_codepoints, decode_vs_stego, find_vs_runs, is_vs_codepoint, shannon_entropy,
    DecodedPayload, PayloadClass,
};

pub use detector::Detector;

#[cfg(feature = "semantic")]
pub use detector::SemanticDetector;

pub use detectors::{
    BidiDetector, GlasswareDetector, HomoglyphDetector, InvisibleCharDetector, UnicodeTagDetector,
};

pub use encrypted_payload_detector::EncryptedPayloadDetector;

pub use engine::{ScanEngine, ScanResult};

pub use finding::{DetectionCategory, Severity, SourceLocation};

pub use header_c2_detector::HeaderC2Detector;

pub use ranges::{CRITICAL_RANGES, INVISIBLE_RANGES};

pub use scanner::{scan, ScanSessionStats, UnicodeScanner};

pub use script_detector::{
    get_script, get_scripts_in_identifier, has_mixed_scripts, is_high_risk_script, is_pure_latin,
    is_pure_non_latin,
};

#[cfg(feature = "semantic")]
pub use semantic::{build_semantic, SemanticAnalysis};

#[cfg(feature = "semantic")]
pub use taint::{
    calculate_entropy, check_flows, find_sinks, find_sources, DynExecKind, FlowKind, TaintFlow,
    TaintSink, TaintSource,
};

#[cfg(feature = "semantic")]
pub use gw005_semantic::Gw005SemanticDetector;

#[cfg(feature = "semantic")]
pub use gw006_semantic::Gw006SemanticDetector;

#[cfg(feature = "semantic")]
pub use gw007_semantic::Gw007SemanticDetector;

#[cfg(feature = "semantic")]
pub use gw008_semantic::Gw008SemanticDetector;

pub use unicode_detector::UnicodeDetector;

// Re-export Finding as the main type (aliased from UnicodeFinding for backwards compatibility)
pub use finding::Finding;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_variation_selector() {
        let content = "const secret\u{FE00}Key = 'value';";
        let findings = scan(content, "test.js");

        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.category == DetectionCategory::InvisibleCharacter));
    }

    #[test]
    fn test_scan_homoglyph() {
        let content = "const pаssword = 'secret';"; // Cyrillic 'а'
        let findings = scan(content, "test.js");

        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.category == DetectionCategory::Homoglyph));
    }

    #[test]
    fn test_scan_bidi() {
        let content = "const file = \"test\u{202E}exe\";";
        let findings = scan(content, "test.js");

        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.category == DetectionCategory::BidirectionalOverride));
    }

    #[test]
    fn test_clean_content() {
        let content = "const normal = 'hello world';";
        let findings = scan(content, "test.js");

        assert!(findings.is_empty());
    }
}
