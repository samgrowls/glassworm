//! GW008 Semantic Detector
//!
//! Detects header-based C2 patterns — extracting encrypted commands from HTTP headers,
//! decrypting them, and executing them dynamically.

use crate::detector::SemanticDetector;
use crate::finding::{DetectionCategory, Finding, Severity};
use crate::taint::{FlowKind, TaintFlow, TaintSink, TaintSource};
use std::path::Path;

/// Semantic detector for GW008 - Header-based C2
///
/// Detects HTTP header extraction combined with decryption and dynamic execution,
/// indicating potential C2 payload delivery (GlassWare Wave 4-5 pattern).
pub struct Gw008SemanticDetector;

impl Gw008SemanticDetector {
    /// Create a new GW008 semantic detector
    pub fn new() -> Self {
        Self
    }
}

impl Default for Gw008SemanticDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for Gw008SemanticDetector {
    fn id(&self) -> &str {
        "GW008"
    }

    fn detect_semantic(
        &self,
        source_code: &str,
        path: &Path,
        flows: &[TaintFlow],
        sources: &[TaintSource],
        _sinks: &[TaintSink],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Step 1: Find all CryptoApiCall → DynamicExec flows
        let crypto_exec_flows: Vec<_> = flows
            .iter()
            .filter(|f| {
                matches!(f.source, TaintSource::CryptoApiCall { .. })
                    && matches!(f.sink, TaintSink::DynamicExec { .. })
            })
            .collect();

        // Step 2: For each such flow, check if an HttpHeaderAccess source
        // exists (we check presence, detailed scope analysis is done by flow tracking)
        for flow in &crypto_exec_flows {
            let has_header = sources
                .iter()
                .any(|s| matches!(s, TaintSource::HttpHeaderAccess { .. }));

            if has_header {
                let (severity, confidence) = match &flow.flow_kind {
                    FlowKind::Direct | FlowKind::Transitive { .. } => (Severity::Critical, "high"),
                    FlowKind::SameScope => (Severity::High, "medium"),
                };

                findings.push(Finding::new(
                    &path.to_string_lossy(),
                    byte_offset_to_line(source_code, flow.source.span().0),
                    1,
                    0,
                    '\0',
                    DetectionCategory::HeaderC2,
                    severity,
                    &format!(
                        "Header-based C2 pattern: HTTP header extraction + {} decryption \
                         flows to {} (confidence: {})",
                        crypto_method_name(&flow.source),
                        sink_description(&flow.sink),
                        confidence,
                    ),
                    "CRITICAL: This code exhibits the GlassWare C2 pattern. HTTP response headers \
                     are being used as a covert channel to deliver encrypted payloads. The data is \
                     extracted from headers, decrypted, and executed dynamically.",
                ));
            }
        }

        findings
    }
}

fn crypto_method_name(source: &TaintSource) -> &str {
    match source {
        TaintSource::CryptoApiCall { method, .. } => method.as_str(),
        _ => "unknown",
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
        let detector = Gw008SemanticDetector::new();
        assert_eq!(detector.id(), "GW008");
    }

    #[test]
    fn test_no_flows_no_findings() {
        let detector = Gw008SemanticDetector::new();
        let path = Path::new("test.js");
        let flows = vec![];
        let sources = vec![];
        let sinks = vec![];

        let findings = detector.detect_semantic("", path, &flows, &sources, &sinks);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_crypto_exec_no_header() {
        let detector = Gw008SemanticDetector::new();
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
        // Should not detect (no HTTP header access)
        assert!(findings.is_empty());
    }

    #[test]
    fn test_header_crypto_exec() {
        let detector = Gw008SemanticDetector::new();
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
        let sources = vec![TaintSource::HttpHeaderAccess {
            header_name: Some("x-command".to_string()),
            span: (50, 70),
            scope_id: 0,
            assigned_to: None,
        }];
        let sinks = vec![];

        let findings = detector.detect_semantic("", path, &flows, &sources, &sinks);
        // Should detect (all three components present)
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, DetectionCategory::HeaderC2);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_header_exec_no_crypto() {
        let detector = Gw008SemanticDetector::new();
        let path = Path::new("test.js");
        let sources = vec![TaintSource::HttpHeaderAccess {
            header_name: Some("x-command".to_string()),
            span: (0, 20),
            scope_id: 0,
            assigned_to: None,
        }];
        let sinks = vec![TaintSink::DynamicExec {
            kind: crate::taint::DynExecKind::Eval,
            span: (30, 40),
            scope_id: 0,
            arg_spans: vec![(35, 39)],
        }];
        let flows = vec![];

        let findings = detector.detect_semantic("", path, &flows, &sources, &sinks);
        // Should not detect (no crypto)
        assert!(findings.is_empty());
    }

    #[test]
    fn test_header_crypto_no_exec() {
        let detector = Gw008SemanticDetector::new();
        let path = Path::new("test.js");
        let sources = vec![
            TaintSource::HttpHeaderAccess {
                header_name: Some("x-token".to_string()),
                span: (0, 20),
                scope_id: 0,
                assigned_to: None,
            },
            TaintSource::CryptoApiCall {
                method: "createDecipheriv".to_string(),
                span: (30, 50),
                scope_id: 0,
                assigned_to: None,
                has_hardcoded_key: false,
                key_value: None,
            },
        ];
        let sinks = vec![];
        let flows = vec![];

        let findings = detector.detect_semantic("", path, &flows, &sources, &sinks);
        // Should not detect (no dynamic execution in flow)
        assert!(findings.is_empty());
    }
}
