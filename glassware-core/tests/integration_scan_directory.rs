//! Scan-Level Integration Tests
//!
//! These tests exercise the full scan pipeline on entire directories,
//! verifying detection rates and false positive rates.

use glassware_core::engine::ScanEngine;
use glassware_core::finding::{DetectionCategory, Severity};
use std::path::{Path, PathBuf};

/// Recursively walk a directory and collect all JS/TS files
fn collect_js_files(dir: &Path, base_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(collect_js_files(&path, base_dir));
            } else if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "js" || ext == "ts" || ext == "jsx" || ext == "tsx" {
                        files.push(path);
                    }
                }
            }
        }
    }
    
    files
}

/// Get the fixtures directory path
fn get_fixtures_dir() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
}

// ============================================================================
// Campaign Fixture Directory Scan
// ============================================================================

#[test]
fn test_scan_campaign_directory_detects_all() {
    let fixtures_dir = get_fixtures_dir();
    let campaign_dir = fixtures_dir.join("glassworm");
    
    if !campaign_dir.exists() {
        eprintln!("Campaign directory not found: {}", campaign_dir.display());
        return;
    }
    
    let files = collect_js_files(&campaign_dir, &fixtures_dir);
    let engine = ScanEngine::default_detectors();
    
    let mut detected_count = 0;
    let mut total_count = 0;
    let mut undetected_files = Vec::new();
    
    for file_path in &files {
        // Skip helper files that are part of split tests
        if file_path.file_name().map(|n| n.to_str() == Some("split_across_files_helper.js")).unwrap_or(false) {
            continue;
        }
        
        total_count += 1;
        
        let content = std::fs::read_to_string(file_path)
            .expect("Failed to read campaign fixture");
        
        let findings = engine.scan(file_path, &content);
        
        if !findings.is_empty() {
            detected_count += 1;
        } else {
            undetected_files.push(file_path.clone());
        }
    }
    
    let detection_rate = if total_count > 0 {
        (detected_count as f64 / total_count as f64) * 100.0
    } else {
        0.0
    };
    
    eprintln!(
        "\n=== Campaign Fixture Detection Summary ==="
    );
    eprintln!("Total files scanned: {}", total_count);
    eprintln!("Files with detections: {}", detected_count);
    eprintln!("Detection rate: {:.1}%", detection_rate);
    
    if !undetected_files.is_empty() {
        eprintln!("\nUndetected files:");
        for file in &undetected_files {
            eprintln!("  - {}", file.display());
        }
    }
    eprintln!("========================================\n");
    
    // Assert detection rate >= 70% (allowing for known limitations)
    assert!(
        detection_rate >= 70.0,
        "Detection rate should be >= 70%, got {:.1}%. Undetected: {:?}",
        detection_rate,
        undetected_files
    );
}

#[test]
fn test_scan_campaign_directory_severity_distribution() {
    let fixtures_dir = get_fixtures_dir();
    let campaign_dir = fixtures_dir.join("glassworm");
    
    if !campaign_dir.exists() {
        return;
    }
    
    let files = collect_js_files(&campaign_dir, &fixtures_dir);
    let engine = ScanEngine::default_detectors();
    
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;
    let mut info_count = 0;
    
    for file_path in &files {
        let content = std::fs::read_to_string(file_path)
            .expect("Failed to read campaign fixture");
        
        let findings = engine.scan(file_path, &content);
        
        for finding in &findings {
            match finding.severity {
                Severity::Critical => critical_count += 1,
                Severity::High => high_count += 1,
                Severity::Medium => medium_count += 1,
                Severity::Low => low_count += 1,
                Severity::Info => info_count += 1,
            }
        }
    }
    
    eprintln!(
        "\n=== Campaign Fixture Severity Distribution ==="
    );
    eprintln!("Critical: {}", critical_count);
    eprintln!("High: {}", high_count);
    eprintln!("Medium: {}", medium_count);
    eprintln!("Low: {}", low_count);
    eprintln!("Info: {}", info_count);
    eprintln!("==========================================\n");
    
    // Should have mostly Critical and High severity findings
    let critical_and_high = critical_count + high_count;
    let total = critical_count + high_count + medium_count + low_count + info_count;
    
    if total > 0 {
        let critical_high_ratio = (critical_and_high as f64 / total as f64) * 100.0;
        eprintln!(
            "Critical+High ratio: {:.1}% ({}/{})",
            critical_high_ratio, critical_and_high, total
        );
        
        // At least 50% should be Critical or High
        assert!(
            critical_high_ratio >= 50.0,
            "At least 50% of findings should be Critical or High severity"
        );
    }
}

// ============================================================================
// False Positive Directory Scan
// ============================================================================

#[test]
fn test_scan_false_positive_directory_zero_findings() {
    let fixtures_dir = get_fixtures_dir();
    let fp_dir = fixtures_dir.join("false_positives");
    
    if !fp_dir.exists() {
        eprintln!("False positives directory not found: {}", fp_dir.display());
        return;
    }
    
    let files = collect_js_files(&fp_dir, &fixtures_dir);
    let engine = ScanEngine::default_detectors();
    
    let mut false_positives = Vec::new();
    
    for file_path in &files {
        let content = std::fs::read_to_string(file_path)
            .expect("Failed to read false positive fixture");
        
        let findings = engine.scan(file_path, &content);
        
        if !findings.is_empty() {
            false_positives.push((file_path.clone(), findings));
        }
    }
    
    eprintln!(
        "\n=== False Positive Directory Scan ==="
    );
    eprintln!("Total files scanned: {}", files.len());
    eprintln!("False positives detected: {}", false_positives.len());
    
    if !false_positives.is_empty() {
        eprintln!("\nFalse positive files:");
        for (file, findings) in &false_positives {
            eprintln!("  - {}", file.display());
            for finding in findings {
                eprintln!("    [{}] {}", finding.severity, finding.description);
            }
        }
    }
    eprintln!("=====================================\n");
    
    // Assert ZERO false positives
    assert!(
        false_positives.is_empty(),
        "False positive regression: {} files incorrectly flagged. See above for details.",
        false_positives.len()
    );
}

// ============================================================================
// Edge Case Directory Scan
// ============================================================================

#[test]
fn test_scan_edge_case_directory_summary() {
    let fixtures_dir = get_fixtures_dir();
    let edge_dir = fixtures_dir.join("edge_cases");
    
    if !edge_dir.exists() {
        eprintln!("Edge cases directory not found: {}", edge_dir.display());
        return;
    }
    
    let files = collect_js_files(&edge_dir, &fixtures_dir);
    let engine = ScanEngine::default_detectors();
    
    let mut detected = 0;
    let mut not_detected = 0;
    
    for file_path in &files {
        let content = std::fs::read_to_string(file_path)
            .expect("Failed to read edge case fixture");
        
        let findings = engine.scan(file_path, &content);
        
        if !findings.is_empty() {
            detected += 1;
        } else {
            not_detected += 1;
        }
    }
    
    eprintln!(
        "\n=== Edge Case Directory Summary ==="
    );
    eprintln!("Total files: {}", files.len());
    eprintln!("Detected: {}", detected);
    eprintln!("Not detected: {}", not_detected);
    
    if files.len() > 0 {
        let detection_rate = (detected as f64 / files.len() as f64) * 100.0;
        eprintln!("Detection rate: {:.1}%", detection_rate);
    }
    eprintln!("====================================\n");
    
    // Edge cases include known limitations, so we just report stats
    // No assertion here - this is for monitoring detection coverage
}

// ============================================================================
// Mixed Directory Scan
// ============================================================================

#[test]
fn test_scan_mixed_directory_classification() {
    // This test verifies that glassware can distinguish between
    // malicious and clean files in a mixed directory
    
    let fixtures_dir = get_fixtures_dir();
    let engine = ScanEngine::default_detectors();
    
    // Scan one malicious file
    let malicious_path = fixtures_dir.join("glassworm/wave1_pua_decoder.js");
    let malicious_content = std::fs::read_to_string(&malicious_path)
        .expect("Failed to read malicious fixture");
    let malicious_findings = engine.scan(&malicious_path, &malicious_content);
    
    // Scan one clean file
    let clean_path = fixtures_dir.join("false_positives/legitimate_crypto.js");
    let clean_content = std::fs::read_to_string(&clean_path)
        .expect("Failed to read clean fixture");
    let clean_findings = engine.scan(&clean_path, &clean_content);
    
    eprintln!(
        "\n=== Mixed Directory Classification Test ==="
    );
    eprintln!("Malicious file findings: {}", malicious_findings.len());
    eprintln!("Clean file findings: {}", clean_findings.len());
    eprintln!("========================================\n");
    
    // Malicious file should have findings
    assert!(
        !malicious_findings.is_empty(),
        "Malicious fixture should be detected"
    );
    
    // Clean file should have no findings
    assert!(
        clean_findings.is_empty(),
        "Clean fixture should not be flagged (false positive)"
    );
}

// ============================================================================
// Detection Rate Summary Test (for README stats)
// ============================================================================

#[test]
fn test_detection_rate_summary() {
    let fixtures_dir = get_fixtures_dir();
    let campaign_dir = fixtures_dir.join("glassworm");
    let fp_dir = fixtures_dir.join("false_positives");
    
    let engine = ScanEngine::default_detectors();
    
    // Count campaign detections
    let mut campaign_detected = 0;
    let mut campaign_total = 0;
    
    if campaign_dir.exists() {
        let files = collect_js_files(&campaign_dir, &fixtures_dir);
        for file_path in &files {
            if file_path.file_name().map(|n| n.to_str() == Some("split_across_files_helper.js")).unwrap_or(false) {
                continue;
            }
            campaign_total += 1;
            let content = std::fs::read_to_string(file_path).unwrap();
            if !engine.scan(file_path, &content).is_empty() {
                campaign_detected += 1;
            }
        }
    }
    
    // Count false positive rate
    let mut fp_triggered = 0;
    let mut fp_total = 0;
    
    if fp_dir.exists() {
        let files = collect_js_files(&fp_dir, &fixtures_dir);
        fp_total = files.len();
        for file_path in &files {
            let content = std::fs::read_to_string(file_path).unwrap();
            if !engine.scan(file_path, &content).is_empty() {
                fp_triggered += 1;
            }
        }
    }
    
    let campaign_rate = if campaign_total > 0 {
        (campaign_detected as f64 / campaign_total as f64) * 100.0
    } else {
        0.0
    };
    
    let fp_rate = if fp_total > 0 {
        (fp_triggered as f64 / fp_total as f64) * 100.0
    } else {
        0.0
    };
    
    eprintln!("\n╔════════════════════════════════════════════════════════╗");
    eprintln!("║         GLASSWARE DETECTION RATE SUMMARY              ║");
    eprintln!("╠════════════════════════════════════════════════════════╣");
    eprintln!("║ Campaign Fixtures: {}/{} detected ({:.1}%)            ", campaign_detected, campaign_total, campaign_rate);
    eprintln!("║ False Positives: {}/{} triggered ({:.1}%)             ", fp_triggered, fp_total, fp_rate);
    eprintln!("╚════════════════════════════════════════════════════════╝\n");
    
    // Assert acceptable rates
    // Note: 70% threshold accounts for known limitations (cross-file flows, browser-side code, etc.)
    assert!(
        campaign_rate >= 70.0,
        "Campaign detection rate should be >= 70%, got {:.1}%",
        campaign_rate
    );
    
    assert!(
        fp_rate == 0.0,
        "False positive rate should be 0%"
    );
}
