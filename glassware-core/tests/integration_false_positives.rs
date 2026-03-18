//! Integration Tests for False Positive Fixtures
//!
//! These tests verify that glassware produces ZERO findings on legitimate code patterns.
//! Any finding on these fixtures is considered a regression.

use glassware_core::engine::ScanEngine;
use std::path::Path;

/// Helper function to scan a fixture file and assert zero findings
fn assert_clean_fixture(relative_path: &str) {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let fixture_path = std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join(relative_path);
    
    let content = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", fixture_path.display(), e));
    
    let engine = ScanEngine::default_detectors();
    let findings = engine.scan(&fixture_path, &content);
    
    assert!(
        findings.is_empty(),
        "FALSE POSITIVE on {}: Found {:?} findings. This legitimate code should not trigger any detections.",
        relative_path,
        findings
    );
}

// ============================================================================
// Legitimate Crypto Usage Tests
// ============================================================================

#[test]
fn test_legitimate_crypto_produces_zero_findings() {
    assert_clean_fixture("false_positives/legitimate_crypto.js");
}

#[test]
fn test_legitimate_crypto_config_produces_zero_findings() {
    assert_clean_fixture("false_positives/legitimate_crypto_config.js");
}

// ============================================================================
// Legitimate High-Entropy Content Tests
// ============================================================================

#[test]
fn test_base64_config_produces_zero_findings() {
    assert_clean_fixture("false_positives/base64_config.js");
}

#[test]
fn test_source_map_produces_zero_findings() {
    assert_clean_fixture("false_positives/source_map.js");
}

#[test]
fn test_svg_data_uri_produces_zero_findings() {
    assert_clean_fixture("false_positives/svg_data_uri.js");
}

// ============================================================================
// Legitimate Fetch Pattern Tests
// ============================================================================

#[test]
fn test_normal_api_client_produces_zero_findings() {
    assert_clean_fixture("false_positives/normal_api_client.js");
}

#[test]
fn test_ssr_fetch_render_produces_zero_findings() {
    assert_clean_fixture("false_positives/ssr_fetch_render.js");
}

// ============================================================================
// Legitimate XOR / Byte Manipulation Tests
// ============================================================================

#[test]
fn test_checksum_xor_produces_zero_findings() {
    assert_clean_fixture("false_positives/checksum_xor.js");
}

#[test]
fn test_buffer_transform_produces_zero_findings() {
    assert_clean_fixture("false_positives/buffer_transform.js");
}

// ============================================================================
// Legitimate Unicode Handling Tests
// ============================================================================

#[test]
fn test_unicode_normalization_produces_zero_findings() {
    assert_clean_fixture("false_positives/unicode_normalization.js");
}

#[test]
fn test_i18n_locale_check_produces_zero_findings() {
    assert_clean_fixture("false_positives/i18n_locale_check.js");
}

// ============================================================================
// Legitimate childProcess Usage Tests
// ============================================================================

#[test]
fn test_build_script_produces_zero_findings() {
    assert_clean_fixture("false_positives/build_script.js");
}

// ============================================================================
// Comprehensive False Positive Rate Test
// ============================================================================

#[test]
fn test_all_false_positive_fixtures_clean() {
    /// List of all false positive fixture files
    const FP_FIXTURES: &[&str] = &[
        "false_positives/legitimate_crypto.js",
        "false_positives/legitimate_crypto_config.js",
        "false_positives/base64_config.js",
        "false_positives/source_map.js",
        "false_positives/svg_data_uri.js",
        "false_positives/normal_api_client.js",
        "false_positives/ssr_fetch_render.js",
        "false_positives/checksum_xor.js",
        "false_positives/buffer_transform.js",
        "false_positives/unicode_normalization.js",
        "false_positives/i18n_locale_check.js",
        "false_positives/build_script.js",
    ];
    
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let engine = ScanEngine::default_detectors();
    
    let mut false_positives = Vec::new();
    
    for fixture in FP_FIXTURES {
        let fixture_path = std::path::Path::new(&manifest_dir)
            .join("tests")
            .join("fixtures")
            .join(fixture);
        
        if !fixture_path.exists() {
            eprintln!("Warning: Fixture file not found: {}", fixture_path.display());
            continue;
        }
        
        let content = std::fs::read_to_string(&fixture_path)
            .expect("Failed to read fixture");
        
        let findings = engine.scan(&fixture_path, &content);
        
        if !findings.is_empty() {
            false_positives.push((fixture.to_string(), findings));
        }
    }
    
    if !false_positives.is_empty() {
        eprintln!("\n=== FALSE POSITIVE REGRESSION DETECTED ===");
        for (fixture, findings) in &false_positives {
            eprintln!("\nFixture: {}", fixture);
            for finding in findings {
                eprintln!("  - [{}] {}", finding.severity, finding.description);
            }
        }
        eprintln!("==========================================\n");
    }
    
    assert!(
        false_positives.is_empty(),
        "False positive regression detected on {} fixtures. See above for details.",
        false_positives.len()
    );
}
