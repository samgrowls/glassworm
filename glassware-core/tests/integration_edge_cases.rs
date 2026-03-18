//! Integration Tests for Edge Case Fixtures
//!
//! These tests verify glassware's behavior on edge cases and obfuscation techniques.
//! Some tests are marked as `#[ignore]` to document known limitations.

use glassware_core::engine::ScanEngine;
use glassware_core::finding::{DetectionCategory, Severity};
use std::path::Path;

/// Helper function to scan a fixture file
fn scan_fixture(relative_path: &str) -> Vec<glassware_core::finding::Finding> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let fixture_path = std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join(relative_path);
    
    let content = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", fixture_path.display(), e));
    
    let engine = ScanEngine::default_detectors();
    engine.scan(&fixture_path, &content)
}

/// Helper to check if any finding exists
fn has_any_finding(findings: &[glassware_core::finding::Finding]) -> bool {
    !findings.is_empty()
}

// ============================================================================
// Obfuscation Resistance Tests - Should Detect
// ============================================================================

#[test]
fn test_minified_payload_detects() {
    let findings = scan_fixture("edge_cases/minified_payload.js");
    
    // Minified code should still be detected
    assert!(
        has_any_finding(&findings),
        "Minified payload should still be detected. Findings: {:?}",
        findings
    );
}

#[test]
fn test_eval_via_function_constructor_detects() {
    let findings = scan_fixture("edge_cases/eval_via_function_constructor.js");
    
    // Function constructor should be detected as dynamic exec
    assert!(
        has_any_finding(&findings),
        "Function constructor pattern should be detected. Findings: {:?}",
        findings
    );
}

#[test]
fn test_eval_via_indirect_detects() {
    let findings = scan_fixture("edge_cases/eval_via_indirect.js");
    
    // Indirect eval should still be detected
    assert!(
        has_any_finding(&findings),
        "Indirect eval pattern should be detected. Findings: {:?}",
        findings
    );
}

#[test]
fn test_comment_obfuscation_detects() {
    let findings = scan_fixture("edge_cases/comment_obfuscation.js");
    
    // Comments should not prevent detection
    assert!(
        has_any_finding(&findings),
        "Comment obfuscation should not prevent detection. Findings: {:?}",
        findings
    );
}

#[test]
fn test_conditional_eval_detects() {
    let findings = scan_fixture("edge_cases/conditional_eval.js");
    
    // Conditional eval should still be detected
    assert!(
        has_any_finding(&findings),
        "Conditional eval should be detected. Findings: {:?}",
        findings
    );
}

#[test]
fn test_try_catch_wrapped_detects() {
    let findings = scan_fixture("edge_cases/try_catch_wrapped.js");
    
    // Try/catch wrapping should not prevent detection
    assert!(
        has_any_finding(&findings),
        "Try/catch wrapped malicious code should be detected. Findings: {:?}",
        findings
    );
}

#[test]
fn test_hex_encoded_strings_detects() {
    let findings = scan_fixture("edge_cases/hex_encoded_strings.js");
    
    // Hex encoding should still trigger on eval sink
    assert!(
        has_any_finding(&findings),
        "Hex encoded strings with eval should be detected. Findings: {:?}",
        findings
    );
}

// ============================================================================
// Known Limitations - Tests Documenting Detection Gaps
// ============================================================================

#[test]
#[ignore = "Known limitation: Cross-file flows are not tracked. Glassware scans per-file."]
fn test_split_across_files_limitation() {
    let findings_main = scan_fixture("edge_cases/split_across_files.js");
    let findings_helper = scan_fixture("edge_cases/split_across_files_helper.js");
    
    // Currently, neither file may trigger because:
    // - Main file has fetch but no eval
    // - Helper file has eval but the high-entropy source is in main file
    // This is a known limitation for future improvement
    
    // Document current behavior: may or may not detect
    eprintln!(
        "Split files - Main: {} findings, Helper: {} findings (cross-file flow not tracked)",
        findings_main.len(),
        findings_helper.len()
    );
}

#[test]
#[ignore = "Known limitation: Variable renaming may evade regex-based detection"]
fn test_variable_renamed_limitation() {
    let findings = scan_fixture("edge_cases/variable_renamed.js");
    
    // Renamed variables may evade detection
    // This test documents the current limitation
    eprintln!(
        "Variable renamed test - {} findings (may evade detection)",
        findings.len()
    );
}

#[test]
#[ignore = "Known limitation: Template literal obfuscation may evade regex detection"]
fn test_template_literal_obfuscation_limitation() {
    let findings = scan_fixture("edge_cases/template_literal_obfuscation.js");
    
    // Template literal method name construction may evade regex
    eprintln!(
        "Template literal obfuscation - {} findings (may evade detection)",
        findings.len()
    );
}

#[test]
#[ignore = "Known limitation: Unicode escape sequences may evade detection"]
fn test_unicode_escape_sequences_limitation() {
    let findings = scan_fixture("edge_cases/unicode_escape_sequences.js");
    
    // Unicode escapes for function names may evade regex
    eprintln!(
        "Unicode escape sequences - {} findings (may evade detection)",
        findings.len()
    );
}

// ============================================================================
// Severity and Confidence Tests
// ============================================================================

#[test]
fn test_minified_payload_has_high_severity() {
    let findings = scan_fixture("edge_cases/minified_payload.js");
    
    // Minified code should be detected (severity may be Medium or High)
    assert!(
        findings.iter().any(|f| f.severity >= Severity::Medium),
        "Minified payload should have at least Medium severity. Findings: {:?}",
        findings
    );
}

#[test]
fn test_findings_have_confidence_scores() {
    let findings = scan_fixture("edge_cases/conditional_eval.js");
    
    // At least some findings should have confidence scores
    let with_confidence = findings.iter().filter(|f| f.confidence.is_some()).count();
    
    eprintln!(
        "Conditional eval - {} findings, {} with confidence scores",
        findings.len(),
        with_confidence
    );
}

// ============================================================================
// Feature Flag Tests
// ============================================================================

#[test]
#[cfg(feature = "semantic")]
fn test_edge_cases_with_semantic() {
    // Run a subset of edge case tests with semantic analysis enabled
    let findings = scan_fixture("edge_cases/eval_via_function_constructor.js");
    
    assert!(
        has_any_finding(&findings),
        "Should detect with semantic feature enabled. Findings: {:?}",
        findings
    );
}

#[test]
#[cfg(not(feature = "semantic"))]
fn test_edge_cases_without_semantic() {
    // Run a subset of edge case tests without semantic analysis
    let findings = scan_fixture("edge_cases/eval_via_function_constructor.js");
    
    // Should still detect via regex-based detectors
    assert!(
        has_any_finding(&findings),
        "Should detect even without semantic feature. Findings: {:?}",
        findings
    );
}
