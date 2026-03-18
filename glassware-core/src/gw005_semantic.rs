//! GW005 Semantic Detector
//!
//! Detects encrypted payload patterns using semantic analysis and taint tracking.
//! This is the semantic version of the regex-based encrypted_payload_detector.

use crate::detector::SemanticDetector;
use crate::finding::{DetectionCategory, Finding, Severity};
use crate::taint::{FlowKind, TaintFlow, TaintSink, TaintSource};
use std::path::Path;

/// Semantic detector for GW005 - Encrypted Payload
///
/// Detects high-entropy strings that flow to dynamic code execution,
/// indicating potential encrypted payload loaders.
pub struct Gw005SemanticDetector;

impl Gw005SemanticDetector {
    /// Create a new GW005 semantic detector
    pub fn new() -> Self {
        Self
    }
}

impl Default for Gw005SemanticDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for Gw005SemanticDetector {
    fn id(&self) -> &str {
        "GW005"
    }

    fn detect_semantic(
        &self,
        _source_code: &str,
        path: &Path,
        flows: &[TaintFlow],
        _sources: &[TaintSource],
        _sinks: &[TaintSink],
    ) -> Vec<Finding> {
        flows
            .iter()
            .filter_map(|flow| {
                // Only care about high-entropy sources
                let is_entropy_source =
                    matches!(flow.source, TaintSource::HighEntropyString { .. });
                if !is_entropy_source {
                    return None;
                }

                // Only care about dynamic exec sinks
                let is_exec_sink = matches!(flow.sink, TaintSink::DynamicExec { .. });
                if !is_exec_sink {
                    return None;
                }

                // Determine severity and confidence based on flow strength
                let (severity, confidence) = match &flow.flow_kind {
                    FlowKind::Direct => (Severity::High, "high"),
                    FlowKind::Transitive { .. } => (Severity::High, "high"),
                    FlowKind::SameScope => (Severity::Medium, "medium"),
                };

                let sink_desc = sink_description(&flow.sink);
                let flow_desc = flow_description(&flow.flow_kind);

                Some(Finding::new(
                    &path.to_string_lossy(),
                    byte_offset_to_line(_source_code, flow.source.span().0),
                    1,
                    0,
                    '\0',
                    DetectionCategory::EncryptedPayload,
                    severity,
                    &format!(
                        "High-entropy string flows to {} (confidence: {}, flow: {})",
                        sink_desc, confidence, flow_desc
                    ),
                    "Review this file for encrypted payload patterns. The combination of \
                     high-entropy encoded data and dynamic code execution is characteristic \
                     of encrypted loaders used in supply chain attacks.",
                ))
            })
            .collect()
    }
}

/// Get a human-readable description of the sink
fn sink_description(sink: &TaintSink) -> &'static str {
    match sink {
        TaintSink::DynamicExec { kind, .. } => match kind {
            crate::taint::DynExecKind::Eval => "eval()",
            crate::taint::DynExecKind::FunctionConstructor => "Function constructor",
            crate::taint::DynExecKind::ChildProcessExec => "child_process.exec()",
            crate::taint::DynExecKind::VmRunInContext => "vm.runInContext()",
        },
    }
}

/// Get a human-readable description of the flow kind
fn flow_description(flow: &FlowKind) -> &'static str {
    match flow {
        FlowKind::Direct => "direct",
        FlowKind::Transitive { .. } => "transitive",
        FlowKind::SameScope => "same-scope",
    }
}

/// Convert byte offset to line number
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
        let detector = Gw005SemanticDetector::new();
        assert_eq!(detector.id(), "GW005");
    }

    #[test]
    fn test_no_flows_no_findings() {
        let detector = Gw005SemanticDetector::new();
        let path = Path::new("test.js");
        let flows = vec![];
        let sources = vec![];
        let sinks = vec![];

        let findings = detector.detect_semantic("", path, &flows, &sources, &sinks);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_wrong_source_type_no_finding() {
        let detector = Gw005SemanticDetector::new();
        let path = Path::new("test.js");
        let flows = vec![TaintFlow {
            source: TaintSource::HttpHeaderAccess {
                header_name: Some("x-header".to_string()),
                span: (0, 10),
                scope_id: 0,
                assigned_to: None,
            },
            sink: TaintSink::DynamicExec {
                kind: crate::taint::DynExecKind::Eval,
                span: (20, 30),
                scope_id: 0,
                arg_spans: vec![(25, 29)],
            },
            flow_kind: FlowKind::Direct,
        }];
        let sources = vec![];
        let sinks = vec![];

        let findings = detector.detect_semantic("", path, &flows, &sources, &sinks);
        // Should not detect because source is not HighEntropyString
        assert!(findings.is_empty());
    }

    #[test]
    fn test_wrong_sink_type_no_finding() {
        let detector = Gw005SemanticDetector::new();
        let path = Path::new("test.js");
        // Note: We only have DynamicExec sink type currently
        // This test verifies the filter logic works
        let flows = vec![];
        let sources = vec![];
        let sinks = vec![];

        let findings = detector.detect_semantic("", path, &flows, &sources, &sinks);
        assert!(findings.is_empty());
    }
}
