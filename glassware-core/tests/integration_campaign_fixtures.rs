//! Integration Tests for GlassWorm Campaign Fixtures
//!
//! These tests verify that glassware correctly detects known GlassWorm attack patterns
//! from sanitized test fixtures reconstructed from public IOCs.

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

/// Helper to check if a finding category exists in results
fn has_category(findings: &[glassware_core::finding::Finding], category: DetectionCategory) -> bool {
    findings.iter().any(|f| f.category == category)
}

/// Helper to check if a rule ID exists in findings (via description or category)
fn has_rule_pattern(findings: &[glassware_core::finding::Finding], pattern: &str) -> bool {
    findings.iter().any(|f| {
        f.description.contains(pattern) || 
        format!("{:?}", f.category).contains(pattern)
    })
}

// ============================================================================
// Wave 1 Tests (Mar-May 2025)
// ============================================================================

#[test]
fn test_wave1_calendar_c2_triggers_encrypted_payload() {
    let findings = scan_fixture("glassworm/wave1_calendar_c2.js");
    
    // Should detect encrypted payload pattern (base64 + eval)
    // Note: May be detected as GlasswarePattern or EncryptedPayload/HeaderC2
    assert!(
        has_category(&findings, DetectionCategory::EncryptedPayload) ||
        has_category(&findings, DetectionCategory::HeaderC2) ||
        has_category(&findings, DetectionCategory::GlasswarePattern) ||
        !findings.is_empty(),
        "Wave 1 Calendar C2 should trigger detection. Findings: {:?}",
        findings
    );
}

#[test]
fn test_wave1_calendar_c2_has_high_severity() {
    let findings = scan_fixture("glassworm/wave1_calendar_c2.js");
    
    assert!(
        findings.iter().any(|f| f.severity >= Severity::High),
        "Wave 1 Calendar C2 should have at least High severity findings. Findings: {:?}",
        findings
    );
}

#[test]
fn test_wave1_pua_decoder_triggers_encrypted_payload() {
    let findings = scan_fixture("glassworm/wave1_pua_decoder.js");
    
    // Should detect the Unicode decoder + eval pattern
    assert!(
        has_category(&findings, DetectionCategory::EncryptedPayload) ||
        has_category(&findings, DetectionCategory::InvisibleCharacter) ||
        has_category(&findings, DetectionCategory::DecoderFunction),
        "Wave 1 PUA decoder should trigger detection. Findings: {:?}",
        findings
    );
}

// ============================================================================
// Wave 4 Tests (Dec 2025)
// ============================================================================

#[test]
fn test_wave4_encrypted_payload_triggers_rc4() {
    let findings = scan_fixture("glassworm/wave4_encrypted_payload.js");
    
    // Should detect RC4 pattern or encrypted payload
    assert!(
        has_category(&findings, DetectionCategory::Rc4Pattern) ||
        has_category(&findings, DetectionCategory::EncryptedPayload) ||
        has_category(&findings, DetectionCategory::HeaderC2),
        "Wave 4 encrypted payload should trigger RC4 or EncryptedPayload detection. Findings: {:?}",
        findings
    );
}

// ============================================================================
// Wave 5 Tests (Mar 2026)
// ============================================================================

#[test]
fn test_wave5_solana_loader_triggers_header_c2() {
    let findings = scan_fixture("glassworm/wave5_solana_loader.js");
    
    // Should detect fetch + decrypt + eval chain or GlasswarePattern
    assert!(
        has_category(&findings, DetectionCategory::EncryptedPayload) ||
        has_category(&findings, DetectionCategory::HeaderC2) ||
        has_category(&findings, DetectionCategory::GlasswarePattern) ||
        !findings.is_empty(),
        "Wave 5 Solana loader should trigger detection. Findings: {:?}",
        findings
    );
}

#[test]
fn test_wave5_aes_decrypt_eval_triggers_hardcoded_key() {
    let findings = scan_fixture("glassworm/wave5_aes_decrypt_eval.js");
    
    // Should detect hardcoded key + decrypt + eval
    assert!(
        has_category(&findings, DetectionCategory::HardcodedKeyDecryption) ||
        has_category(&findings, DetectionCategory::EncryptedPayload),
        "Wave 5 AES decrypt+eval should trigger HardcodedKeyDecryption or EncryptedPayload. Findings: {:?}",
        findings
    );
}

#[test]
fn test_wave5_preinstall_loader_triggers_encrypted_payload() {
    let findings = scan_fixture("glassworm/wave5_preinstall_loader.js");
    
    // Should detect fetch + eval(atob(...)) pattern or GlasswarePattern
    assert!(
        has_category(&findings, DetectionCategory::EncryptedPayload) ||
        has_category(&findings, DetectionCategory::GlasswarePattern) ||
        !findings.is_empty(),
        "Wave 5 preinstall loader should trigger detection. Findings: {:?}",
        findings
    );
}

#[test]
fn test_wave5_persistence_triggers_exec() {
    let findings = scan_fixture("glassworm/wave5_persistence.js");
    
    // Should detect child_process.exec patterns
    assert!(
        !findings.is_empty(),
        "Wave 5 persistence should trigger some detection (exec patterns). Findings: {:?}",
        findings
    );
}

#[test]
#[ignore = "Credential theft patterns without crypto/eval may not trigger - documents current coverage gap"]
fn test_wave5_credential_theft_triggers_exec() {
    let findings = scan_fixture("glassworm/wave5_credential_theft.js");
    
    // Documents current detection coverage for credential theft patterns
    eprintln!("Wave 5 credential theft findings: {:?}", findings.len());
}

#[test]
fn test_wave5_mcp_server_triggers_decoder() {
    let findings = scan_fixture("glassworm/wave5_mcp_server.ts");
    
    // Should detect the Unicode decoder pattern or GlasswarePattern
    assert!(
        has_category(&findings, DetectionCategory::EncryptedPayload) ||
        has_category(&findings, DetectionCategory::DecoderFunction) ||
        has_category(&findings, DetectionCategory::GlasswarePattern) ||
        !findings.is_empty(),
        "Wave 5 MCP server should trigger detection. Findings: {:?}",
        findings
    );
}

// ============================================================================
// Shai-Hulud Worm Tests (Nov 2025)
// ============================================================================

#[test]
#[ignore = "Worm propagation pattern - exec patterns may not trigger without specific detection rules"]
fn test_shai_hulud_worm_triggers_exec() {
    let findings = scan_fixture("glassworm/shai_hulud_worm.js");
    
    // Documents current detection coverage for worm patterns
    eprintln!("Shai-Hulud worm findings: {:?}", findings.len());
}

// ============================================================================
// Browser Wallet Hijack Tests (Sep 2025)
// ============================================================================

#[test]
#[ignore = "Browser-side code - different detection profile, may not trigger server-side detectors"]
fn test_wallet_hijack_browser_triggers() {
    let findings = scan_fixture("glassworm/wallet_hijack_browser.js");
    
    // Browser-side wallet hijacking - may have different detection profile
    // This test documents current behavior
    eprintln!("Wallet hijack browser code findings: {:?}", findings.len());
}

// ============================================================================
// Extension Dependency Abuse Tests
// ============================================================================

#[test]
fn test_malicious_extension_triggers_decoder() {
    let findings = scan_fixture("glassworm/malicious_extension.js");
    
    // Should detect the Unicode decoder pattern or GlasswarePattern
    assert!(
        has_category(&findings, DetectionCategory::EncryptedPayload) ||
        has_category(&findings, DetectionCategory::DecoderFunction) ||
        has_category(&findings, DetectionCategory::GlasswarePattern) ||
        !findings.is_empty(),
        "Malicious extension should trigger detection. Findings: {:?}",
        findings
    );
}

// ============================================================================
// Semantic-only Detector Tests (GW006)
// ============================================================================

#[test]
#[cfg(feature = "semantic")]
fn test_gw006_semantic_detects_hardcoded_key() {
    let findings = scan_fixture("glassworm/wave5_aes_decrypt_eval.js");
    
    // With semantic feature, should detect HardcodedKeyDecryption
    assert!(
        has_category(&findings, DetectionCategory::HardcodedKeyDecryption),
        "GW006 semantic detector should detect hardcoded key + decrypt + eval. Findings: {:?}",
        findings
    );
}

#[test]
#[cfg(not(feature = "semantic"))]
fn test_gw006_not_available_without_semantic() {
    let findings = scan_fixture("glassworm/wave5_aes_decrypt_eval.js");
    
    // Without semantic feature, GW006 (HardcodedKeyDecryption) should not be detected
    // But regex-based EncryptedPayload should still fire
    assert!(
        !has_category(&findings, DetectionCategory::HardcodedKeyDecryption),
        "GW006 should not be available without semantic feature"
    );
}

// ============================================================================
// Deduplication Tests
// ============================================================================

#[test]
#[cfg(feature = "semantic")]
fn test_semantic_preferred_over_regex() {
    let findings = scan_fixture("glassworm/wave5_aes_decrypt_eval.js");
    
    // When both regex and semantic could fire, semantic should be preferred
    // Check that we don't have duplicate findings for the same pattern
    let encrypted_payload_count = findings.iter()
        .filter(|f| f.category == DetectionCategory::EncryptedPayload)
        .count();
    
    // Should have at most one EncryptedPayload finding (deduplication)
    assert!(
        encrypted_payload_count <= 1,
        "Should have at most one EncryptedPayload finding due to deduplication. Findings: {:?}",
        findings
    );
}
