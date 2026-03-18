//! GW006 Semantic Detector
//!
//! Detects hardcoded cryptographic keys used for decryption followed by dynamic execution.
//! This is the GlassWare Wave 6 pattern: encrypted payloads with embedded keys.

use crate::detector::SemanticDetector;
use crate::finding::{DetectionCategory, Finding, Severity};
use crate::taint::{FlowKind, TaintFlow, TaintSink, TaintSource};
use std::path::Path;

/// Semantic detector for GW006 - Hardcoded Key Decryption
///
/// Detects cryptographic API calls with hardcoded keys where the decrypted
/// result flows to dynamic code execution.
pub struct Gw006SemanticDetector;

impl Gw006SemanticDetector {
    /// Create a new GW006 semantic detector
    pub fn new() -> Self {
        Self
    }
}

impl Default for Gw006SemanticDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for Gw006SemanticDetector {
    fn id(&self) -> &str {
        "GW006"
    }

    fn detect_semantic(
        &self,
        source_code: &str,
        path: &Path,
        flows: &[TaintFlow],
        _sources: &[TaintSource],
        _sinks: &[TaintSink],
    ) -> Vec<Finding> {
        flows
            .iter()
            .filter_map(|flow| {
                // Only care about hardcoded key crypto sources
                let is_hardcoded_crypto = match &flow.source {
                    TaintSource::CryptoApiCall {
                        has_hardcoded_key, ..
                    } => *has_hardcoded_key,
                    _ => false,
                };
                if !is_hardcoded_crypto {
                    return None;
                }

                // Only care about dynamic exec sinks
                let is_exec_sink = matches!(flow.sink, TaintSink::DynamicExec { .. });
                if !is_exec_sink {
                    return None;
                }

                // Determine severity based on flow strength
                let severity = match &flow.flow_kind {
                    FlowKind::Direct | FlowKind::Transitive { .. } => Severity::High,
                    FlowKind::SameScope => Severity::Medium,
                };

                let key_info = match &flow.source {
                    TaintSource::CryptoApiCall {
                        method, key_value, ..
                    } => {
                        let key_preview = key_value
                            .as_ref()
                            .map(|k| {
                                if k.len() > 32 {
                                    format!("{}...", &k[..32])
                                } else {
                                    k.clone()
                                }
                            })
                            .unwrap_or_default();
                        format!("{} with hardcoded key '{}'", method, key_preview)
                    }
                    _ => String::new(),
                };

                let sink_desc = sink_description(&flow.sink);

                Some(Finding::new(
                    &path.to_string_lossy(),
                    byte_offset_to_line(source_code, flow.source.span().0),
                    1,
                    0,
                    '\0',
                    DetectionCategory::HardcodedKeyDecryption,
                    severity,
                    &format!(
                        "Hardcoded-key decryption: {} flows to {}",
                        key_info, sink_desc,
                    ),
                    "Hardcoded cryptographic keys in source code are a strong indicator \
                     of encrypted payload execution. The decrypted result flows to dynamic \
                     code execution, consistent with GlassWare Wave 6 attacks.",
                ))
            })
            .collect()
    }
}

fn sink_description(sink: &TaintSink) -> &str {
    match sink {
        TaintSink::DynamicExec { kind, .. } => match kind {
            crate::taint::DynExecKind::Eval => "eval()",
            crate::taint::DynExecKind::FunctionConstructor => "Function()",
            crate::taint::DynExecKind::ChildProcessExec => "child_process.exec()",
            crate::taint::DynExecKind::VmRunInContext => "vm.runInContext()",
        },
    }
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
        let detector = Gw006SemanticDetector::new();
        assert_eq!(detector.id(), "GW006");
    }

    #[test]
    fn test_hardcoded_key_to_eval() {
        let detector = Gw006SemanticDetector::new();
        let path = Path::new("test.js");
        let flows = vec![TaintFlow {
            source: TaintSource::CryptoApiCall {
                method: "createDecipheriv".to_string(),
                span: (0, 20),
                scope_id: 0,
                assigned_to: None,
                has_hardcoded_key: true,
                key_value: Some("7mK9xP2qL4nR8vB1".to_string()),
            },
            sink: TaintSink::DynamicExec {
                kind: crate::taint::DynExecKind::Eval,
                span: (30, 40),
                scope_id: 0,
                arg_spans: vec![(35, 39)],
            },
            flow_kind: FlowKind::Direct,
        }];
        let sources = vec![];
        let sinks = vec![];

        let findings = detector.detect_semantic("", path, &flows, &sources, &sinks);
        assert!(!findings.is_empty());
        assert_eq!(
            findings[0].category,
            DetectionCategory::HardcodedKeyDecryption
        );
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_no_hardcoded_key_no_finding() {
        let detector = Gw006SemanticDetector::new();
        let path = Path::new("test.js");
        let flows = vec![TaintFlow {
            source: TaintSource::CryptoApiCall {
                method: "createDecipheriv".to_string(),
                span: (0, 20),
                scope_id: 0,
                assigned_to: None,
                has_hardcoded_key: false,
                key_value: None,
            },
            sink: TaintSink::DynamicExec {
                kind: crate::taint::DynExecKind::Eval,
                span: (30, 40),
                scope_id: 0,
                arg_spans: vec![(35, 39)],
            },
            flow_kind: FlowKind::Direct,
        }];
        let sources = vec![];
        let sinks = vec![];

        let findings = detector.detect_semantic("", path, &flows, &sources, &sinks);
        // Should not detect (key is not hardcoded)
        assert!(findings.is_empty());
    }

    #[test]
    fn test_hardcoded_key_no_exec() {
        let detector = Gw006SemanticDetector::new();
        let path = Path::new("test.js");
        let flows = vec![TaintFlow {
            source: TaintSource::CryptoApiCall {
                method: "createDecipheriv".to_string(),
                span: (0, 20),
                scope_id: 0,
                assigned_to: None,
                has_hardcoded_key: true,
                key_value: Some("hardcodedKey123".to_string()),
            },
            sink: TaintSink::DynamicExec {
                kind: crate::taint::DynExecKind::ChildProcessExec,
                span: (30, 40),
                scope_id: 0,
                arg_spans: vec![(35, 39)],
            },
            // No flow - different scopes
            flow_kind: FlowKind::SameScope,
        }];
        let sources = vec![];
        let sinks = vec![];

        let findings = detector.detect_semantic("", path, &flows, &sources, &sinks);
        // Should detect with medium severity (same scope fallback)
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_transitive_flow() {
        let detector = Gw006SemanticDetector::new();
        let path = Path::new("test.js");
        let flows = vec![TaintFlow {
            source: TaintSource::CryptoApiCall {
                method: "crypto.subtle.decrypt".to_string(),
                span: (0, 20),
                scope_id: 0,
                assigned_to: None,
                has_hardcoded_key: true,
                key_value: Some("SGVsbG8gV29ybGQ=".to_string()),
            },
            sink: TaintSink::DynamicExec {
                kind: crate::taint::DynExecKind::Eval,
                span: (30, 40),
                scope_id: 0,
                arg_spans: vec![(35, 39)],
            },
            flow_kind: FlowKind::Transitive {
                through: vec!["decrypted".to_string()],
            },
        }];
        let sources = vec![];
        let sinks = vec![];

        let findings = detector.detect_semantic("", path, &flows, &sources, &sinks);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_no_flows_no_findings() {
        let detector = Gw006SemanticDetector::new();
        let path = Path::new("test.js");
        let flows = vec![];
        let sources = vec![];
        let sinks = vec![];

        let findings = detector.detect_semantic("", path, &flows, &sources, &sinks);
        assert!(findings.is_empty());
    }
}
