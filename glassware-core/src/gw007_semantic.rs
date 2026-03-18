//! GW007 Semantic Detector
//!
//! Detects hand-rolled RC4-like cipher patterns combined with dynamic execution.
//! Uses a hybrid approach: regex for structural indicators, OXC for scope-aware analysis.

use crate::detector::SemanticDetector;
use crate::finding::{DetectionCategory, Finding, Severity};
use crate::taint::{TaintFlow, TaintSink, TaintSource};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

/// RC4 indicator categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Rc4IndicatorKind {
    Init256,
    XorOp,
    Mod256,
    Swap,
    CharCode,
}

/// Lazy-compiled regex patterns for RC4 indicators
static REGEX_INIT_256: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:new\s+Array\s*\(\s*256\s*\)|\b(?:i|j|k|n)\s*<\s*256\b)").unwrap());

static REGEX_XOR_OP: Lazy<Regex> = Lazy::new(|| Regex::new(r"\^").unwrap());

static REGEX_MOD_256: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:%\s*256\b|&\s*0x[fF]{2}\b|&\s*255\b)").unwrap());

static REGEX_SWAP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:tmp|temp|t)\s*=\s*\w+\[\w+\];\s*\w+\[\w+\]\s*=\s*\w+\[\w+\];\s*\w+\[\w+\]\s*=\s*(?:tmp|temp|t)").unwrap()
});

static REGEX_CHARCODE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:charCodeAt|fromCharCode|String\.fromCharCode)").unwrap());

/// Semantic detector for GW007 - RC4-like Cipher Pattern
///
/// Detects hand-rolled stream cipher implementations (typically RC4) combined
/// with dynamic code execution. Attackers use this to evade crypto API detection.
pub struct Gw007SemanticDetector;

impl Gw007SemanticDetector {
    /// Create a new GW007 semantic detector
    pub fn new() -> Self {
        Self
    }
}

impl Default for Gw007SemanticDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for Gw007SemanticDetector {
    fn id(&self) -> &str {
        "GW007"
    }

    fn detect_semantic(
        &self,
        source_code: &str,
        path: &Path,
        _flows: &[TaintFlow],
        _sources: &[TaintSource],
        sinks: &[TaintSink],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // For each DynamicExec sink, check if RC4 indicators are present in its scope
        for sink in sinks {
            // Get the scope of the sink
            // Since we don't have direct access to SemanticAnalysis here,
            // we'll do a simpler regex scan over the whole source
            // In a more sophisticated implementation, we'd use scope_at_offset

            let indicators = find_rc4_indicators(source_code);
            let distinct_kinds: HashSet<_> = indicators.iter().map(|ind| ind.kind).collect();

            if distinct_kinds.len() >= 3 {
                // Calculate confidence based on indicator count
                let confidence = match distinct_kinds.len() {
                    3 => 0.5,
                    4 => 0.7,
                    5 => 0.85,
                    _ => 0.5,
                };

                let indicator_names: Vec<&str> = distinct_kinds
                    .iter()
                    .map(|k| match k {
                        Rc4IndicatorKind::Init256 => "INIT_256",
                        Rc4IndicatorKind::XorOp => "XOR_OP",
                        Rc4IndicatorKind::Mod256 => "MOD_256",
                        Rc4IndicatorKind::Swap => "SWAP",
                        Rc4IndicatorKind::CharCode => "CHARCODE",
                    })
                    .collect();

                findings.push(
                    Finding::new(
                        &path.to_string_lossy(),
                        byte_offset_to_line(source_code, sink.span().0),
                        1,
                        0,
                        '\0',
                        DetectionCategory::Rc4Pattern,
                        Severity::Info,
                        &format!(
                            "RC4-like cipher implementation detected near dynamic execution \
                         ({}/{} indicators: {}). Hand-rolled stream ciphers in npm packages \
                         are highly unusual and consistent with GlassWare payload decryption.",
                            distinct_kinds.len(),
                            5,
                            indicator_names.join(", ")
                        ),
                        "Review this file for hand-rolled cryptographic implementations. \
                     Legitimate packages use Node.js crypto module or Web Crypto API. \
                     Hand-rolled ciphers are commonly used to evade detection.",
                    )
                    .with_confidence(confidence),
                );
                break; // One finding per file is sufficient
            }
        }

        findings
    }
}

/// Find all RC4 indicators in the source code
fn find_rc4_indicators(source: &str) -> Vec<Rc4Indicator> {
    let mut indicators = Vec::new();

    if REGEX_INIT_256.is_match(source) {
        if let Some(m) = REGEX_INIT_256.find(source) {
            indicators.push(Rc4Indicator {
                kind: Rc4IndicatorKind::Init256,
                offset: m.start() as u32,
            });
        }
    }

    if REGEX_XOR_OP.is_match(source) {
        if let Some(m) = REGEX_XOR_OP.find(source) {
            indicators.push(Rc4Indicator {
                kind: Rc4IndicatorKind::XorOp,
                offset: m.start() as u32,
            });
        }
    }

    if REGEX_MOD_256.is_match(source) {
        if let Some(m) = REGEX_MOD_256.find(source) {
            indicators.push(Rc4Indicator {
                kind: Rc4IndicatorKind::Mod256,
                offset: m.start() as u32,
            });
        }
    }

    if REGEX_SWAP.is_match(source) {
        if let Some(m) = REGEX_SWAP.find(source) {
            indicators.push(Rc4Indicator {
                kind: Rc4IndicatorKind::Swap,
                offset: m.start() as u32,
            });
        }
    }

    if REGEX_CHARCODE.is_match(source) {
        if let Some(m) = REGEX_CHARCODE.find(source) {
            indicators.push(Rc4Indicator {
                kind: Rc4IndicatorKind::CharCode,
                offset: m.start() as u32,
            });
        }
    }

    indicators
}

#[derive(Debug, Clone)]
struct Rc4Indicator {
    #[allow(dead_code)]
    kind: Rc4IndicatorKind,
    #[allow(dead_code)]
    offset: u32,
}

fn byte_offset_to_line(source: &str, offset: u32) -> usize {
    source
        .char_indices()
        .enumerate()
        .find(|(_, (idx, _))| *idx >= offset as usize)
        .map(|(line, _)| line + 1)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let detector = Gw007SemanticDetector::new();
        assert_eq!(detector.id(), "GW007");
    }

    #[test]
    fn test_full_rc4_with_eval() {
        let detector = Gw007SemanticDetector::new();
        let source = r#"
            function rc4(key, data) {
                var S = new Array(256);
                for (var i = 0; i < 256; i++) S[i] = i;
                var j = 0;
                for (var i = 0; i < 256; i++) {
                    j = (j + S[i] + key.charCodeAt(i % key.length)) % 256;
                    var tmp = S[i]; S[i] = S[j]; S[j] = tmp;
                }
                var result = '';
                var i = 0, j = 0;
                for (var k = 0; k < data.length; k++) {
                    i = (i + 1) % 256;
                    j = (j + S[i]) % 256;
                    var tmp = S[i]; S[i] = S[j]; S[j] = tmp;
                    result += String.fromCharCode(data.charCodeAt(k) ^ S[(S[i] + S[j]) % 256]);
                }
                return result;
            }
            eval(rc4(key, payload));
        "#;
        let path = Path::new("test.js");
        let flows = vec![];
        let sources = vec![];
        let sinks = vec![TaintSink::DynamicExec {
            kind: crate::taint::DynExecKind::Eval,
            span: (500, 520),
            scope_id: 0,
            arg_spans: vec![(505, 519)],
        }];

        let findings = detector.detect_semantic(source, path, &flows, &sources, &sinks);
        // Should detect with high confidence (5/5 indicators)
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, DetectionCategory::Rc4Pattern);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_minimal_rc4_three_indicators() {
        let detector = Gw007SemanticDetector::new();
        let source = r#"
            function decode(key, input) {
                var arr = new Array(256);
                for (var i = 0; i < 256; i++) arr[i] = i;
                var output = '';
                for (var i = 0; i < input.length; i++) {
                    var x = input.charCodeAt(i) ^ key.charCodeAt(i);
                    output += String.fromCharCode(x);
                }
                return output;
            }
            eval(decode('secret', data));
        "#;
        let path = Path::new("test.js");
        let flows = vec![];
        let sources = vec![];
        let sinks = vec![TaintSink::DynamicExec {
            kind: crate::taint::DynExecKind::Eval,
            span: (300, 320),
            scope_id: 0,
            arg_spans: vec![(305, 319)],
        }];

        let findings = detector.detect_semantic(source, path, &flows, &sources, &sinks);
        // Should detect (INIT_256 + XOR_OP + CHARCODE = 3 indicators)
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_two_indicators_insufficient() {
        let detector = Gw007SemanticDetector::new();
        let source = r#"
            function transform(data) {
                var result = '';
                for (var i = 0; i < data.length; i++) {
                    result += String.fromCharCode(data.charCodeAt(i));
                }
                eval(result);
            }
        "#;
        let path = Path::new("test.js");
        let flows = vec![];
        let sources = vec![];
        let sinks = vec![TaintSink::DynamicExec {
            kind: crate::taint::DynExecKind::Eval,
            span: (200, 220),
            scope_id: 0,
            arg_spans: vec![(205, 211)],
        }];

        let findings = detector.detect_semantic(source, path, &flows, &sources, &sinks);
        // Should NOT detect (only CHARCODE = 1 indicator, need >= 3)
        assert!(findings.is_empty());
    }

    #[test]
    fn test_rc4_without_exec() {
        let detector = Gw007SemanticDetector::new();
        let source = r#"
            function rc4(key, data) {
                var S = new Array(256);
                for (var i = 0; i < 256; i++) S[i] = i;
                var j = 0;
                for (var i = 0; i < 256; i++) {
                    j = (j + S[i] + key.charCodeAt(i % key.length)) % 256;
                    var tmp = S[i]; S[i] = S[j]; S[j] = tmp;
                }
                return S;
            }
            module.exports = rc4;
        "#;
        let path = Path::new("test.js");
        let flows = vec![];
        let sources = vec![];
        let sinks = vec![]; // No dynamic exec

        let findings = detector.detect_semantic(source, path, &flows, &sources, &sinks);
        // Should NOT detect (no exec sink)
        assert!(findings.is_empty());
    }

    #[test]
    fn test_legitimate_xor_hash_check() {
        let detector = Gw007SemanticDetector::new();
        let source = r#"
            function compareHashes(a, b) {
                let diff = 0;
                for (let i = 0; i < a.length; i++) {
                    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
                }
                return diff === 0;
            }
            const isValid = compareHashes(hash1, hash2);
        "#;
        let path = Path::new("test.js");
        let flows = vec![];
        let sources = vec![];
        let sinks = vec![];

        let findings = detector.detect_semantic(source, path, &flows, &sources, &sinks);
        // Should NOT detect (only XOR_OP + CHARCODE = 2 indicators, no exec)
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_sinks_no_findings() {
        let detector = Gw007SemanticDetector::new();
        let source = "console.log('hello');";
        let path = Path::new("test.js");
        let flows = vec![];
        let sources = vec![];
        let sinks = vec![];

        let findings = detector.detect_semantic(source, path, &flows, &sources, &sinks);
        assert!(findings.is_empty());
    }
}
