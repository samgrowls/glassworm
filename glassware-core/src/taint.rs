//! Taint Analysis Module
//!
//! Defines source and sink types for supply chain attack detection,
//! and implements flow checking between them.

#[cfg(feature = "semantic")]
use crate::semantic::SemanticAnalysis;

/// Taint source types
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TaintSource {
    /// High-entropy string (potential encrypted/encoded payload)
    HighEntropyString {
        value: String,
        entropy: f64,
        span: (u32, u32),
        scope_id: u32,
        /// If this string is assigned to a variable, the symbol_id
        assigned_to: Option<u32>,
    },
    /// HTTP header access (potential C2 data)
    HttpHeaderAccess {
        header_name: Option<String>,
        span: (u32, u32),
        scope_id: u32,
        assigned_to: Option<u32>,
    },
    /// Crypto API call (potential decryption)
    CryptoApiCall {
        method: String,
        span: (u32, u32),
        scope_id: u32,
        assigned_to: Option<u32>,
        /// Whether the key argument is a hardcoded string literal
        has_hardcoded_key: bool,
        /// The literal key value if hardcoded
        key_value: Option<String>,
    },
}

/// Taint sink types
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TaintSink {
    /// Dynamic code execution
    DynamicExec {
        kind: DynExecKind,
        span: (u32, u32),
        scope_id: u32,
        /// Spans of the arguments
        arg_spans: Vec<(u32, u32)>,
    },
}

/// Type of dynamic execution
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DynExecKind {
    Eval,
    FunctionConstructor,
    ChildProcessExec,
    VmRunInContext,
}

/// Type of taint flow
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FlowKind {
    /// Source variable is directly used as sink argument
    Direct,
    /// Source variable is assigned to intermediate, which flows to sink
    Transitive { through: Vec<String> },
    /// Source and sink are in same scope (weak signal, fallback)
    SameScope,
}

/// A confirmed taint flow from source to sink
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TaintFlow {
    pub source: TaintSource,
    pub sink: TaintSink,
    pub flow_kind: FlowKind,
}

impl TaintSource {
    /// Get the assigned_to symbol ID if any
    pub fn assigned_to(&self) -> Option<u32> {
        match self {
            TaintSource::HighEntropyString { assigned_to, .. } => *assigned_to,
            TaintSource::HttpHeaderAccess { assigned_to, .. } => *assigned_to,
            TaintSource::CryptoApiCall { assigned_to, .. } => *assigned_to,
        }
    }

    /// Get the scope ID
    pub fn scope_id(&self) -> u32 {
        match self {
            TaintSource::HighEntropyString { scope_id, .. } => *scope_id,
            TaintSource::HttpHeaderAccess { scope_id, .. } => *scope_id,
            TaintSource::CryptoApiCall { scope_id, .. } => *scope_id,
        }
    }

    /// Get the span
    pub fn span(&self) -> (u32, u32) {
        match self {
            TaintSource::HighEntropyString { span, .. } => *span,
            TaintSource::HttpHeaderAccess { span, .. } => *span,
            TaintSource::CryptoApiCall { span, .. } => *span,
        }
    }

    /// Check if this source has a hardcoded key
    pub fn has_hardcoded_key(&self) -> bool {
        match self {
            TaintSource::CryptoApiCall {
                has_hardcoded_key, ..
            } => *has_hardcoded_key,
            _ => false,
        }
    }
}

impl TaintSink {
    /// Get the scope ID
    pub fn scope_id(&self) -> u32 {
        match self {
            TaintSink::DynamicExec { scope_id, .. } => *scope_id,
        }
    }

    /// Get the span
    pub fn span(&self) -> (u32, u32) {
        match self {
            TaintSink::DynamicExec { span, .. } => *span,
        }
    }
}

/// Find all taint sources in the semantic analysis
#[cfg(feature = "semantic")]
pub fn find_sources(sa: &SemanticAnalysis) -> Vec<TaintSource> {
    let mut sources = Vec::new();
    sources.extend(find_high_entropy_strings(sa));
    sources.extend(find_http_header_accesses(sa));
    sources.extend(find_crypto_api_calls(sa));
    sources
}

/// Check if any source of a given type exists in the same scope tree as a reference scope.
#[cfg(feature = "semantic")]
pub fn has_source_in_scope(
    sources: &[TaintSource],
    scope_id: u32,
    sa: &SemanticAnalysis,
    predicate: impl Fn(&TaintSource) -> bool,
) -> bool {
    sources
        .iter()
        .any(|s| predicate(s) && sa.same_scope_or_nested(s.scope_id(), scope_id))
}

/// Find high-entropy string literals
#[cfg(feature = "semantic")]
fn find_high_entropy_strings(sa: &SemanticAnalysis) -> Vec<TaintSource> {
    sa.string_literals
        .iter()
        .filter_map(|lit| {
            if lit.value.len() >= 64 {
                let entropy = calculate_entropy(lit.value.as_bytes());
                if entropy > 4.5 {
                    // Check if this string is assigned to a variable
                    let assigned_to = sa.find_declaration_for_span(lit.span).map(|d| d.symbol_id);
                    return Some(TaintSource::HighEntropyString {
                        value: lit.value.clone(),
                        entropy,
                        span: lit.span,
                        scope_id: lit.scope_id,
                        assigned_to,
                    });
                }
            }
            None
        })
        .collect()
}

/// Find HTTP header access patterns
#[cfg(feature = "semantic")]
fn find_http_header_accesses(sa: &SemanticAnalysis) -> Vec<TaintSource> {
    sa.call_sites
        .iter()
        .filter_map(|call| {
            // Check for header access patterns
            let header_name = if call.callee == "get"
                && call.callee_chain.last() == Some(&"headers".to_string())
            {
                // headers.get('x-header')
                None // Could extract from args if needed
            } else if call.callee_chain.iter().any(|c| c == "headers") {
                // response.headers['x-header'] or similar
                None
            } else {
                return None;
            };

            let assigned_to = sa.find_declaration_for_span(call.span).map(|d| d.symbol_id);

            Some(TaintSource::HttpHeaderAccess {
                header_name,
                span: call.span,
                scope_id: call.scope_id,
                assigned_to,
            })
        })
        .collect()
}

/// Find crypto API calls
#[cfg(feature = "semantic")]
fn find_crypto_api_calls(sa: &SemanticAnalysis) -> Vec<TaintSource> {
    sa.call_sites
        .iter()
        .filter(|call| {
            matches!(
                call.callee.as_str(),
                "createDecipheriv" | "createDecipher" | "createHash" | "createHmac" | "decrypt"
            ) || call.callee_chain.iter().any(|c| c == "crypto")
        })
        .map(|call| {
            let assigned_to = sa.find_declaration_for_span(call.span).map(|d| d.symbol_id);

            // Check if key argument is a hardcoded string literal
            let (has_hardcoded_key, key_value) = if call.callee == "createDecipheriv" {
                // Key is 2nd argument (index 1)
                if let Some(key_arg_span) = call.arg_spans.get(1) {
                    if let Some(lit) = sa.resolves_to_string_literal(*key_arg_span) {
                        (true, Some(lit.value.clone()))
                    } else {
                        (false, None)
                    }
                } else {
                    (false, None)
                }
            } else if call.callee == "createDecipher" {
                // Key is 1st argument (index 0)
                if let Some(key_arg_span) = call.arg_spans.first() {
                    if let Some(lit) = sa.resolves_to_string_literal(*key_arg_span) {
                        (true, Some(lit.value.clone()))
                    } else {
                        (false, None)
                    }
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            };

            TaintSource::CryptoApiCall {
                method: call.callee.clone(),
                span: call.span,
                scope_id: call.scope_id,
                assigned_to,
                has_hardcoded_key,
                key_value,
            }
        })
        .collect()
}

/// Find all taint sinks in the semantic analysis
#[cfg(feature = "semantic")]
pub fn find_sinks(sa: &SemanticAnalysis) -> Vec<TaintSink> {
    sa.call_sites
        .iter()
        .filter_map(|call| {
            let kind = match call.callee.as_str() {
                "eval" => Some(DynExecKind::Eval),
                "Function" => Some(DynExecKind::FunctionConstructor),
                _ if call.callee_chain == ["child_process", "exec"]
                    || call.callee_chain == ["child_process", "execSync"] =>
                {
                    Some(DynExecKind::ChildProcessExec)
                }
                _ if call.callee_chain.last().map(|s| s.as_str()) == Some("runInNewContext")
                    || call.callee_chain.last().map(|s| s.as_str()) == Some("runInContext") =>
                {
                    Some(DynExecKind::VmRunInContext)
                }
                _ => None,
            };
            kind.map(|k| TaintSink::DynamicExec {
                kind: k,
                span: call.span,
                scope_id: call.scope_id,
                arg_spans: call.arg_spans.clone(),
            })
        })
        .collect()
}

/// Check all source→sink flows. Returns confirmed flows.
#[cfg(feature = "semantic")]
pub fn check_flows(
    sa: &SemanticAnalysis,
    sources: &[TaintSource],
    sinks: &[TaintSink],
) -> Vec<TaintFlow> {
    let mut flows = Vec::new();

    for source in sources {
        let source_symbol = source.assigned_to();
        let source_scope = source.scope_id();

        for sink in sinks {
            // LEVEL 1: Direct flow — source symbol appears in sink args
            if let Some(sym_id) = source_symbol {
                let calls = sa.symbol_flows_to_call(sym_id);
                if calls.iter().any(|c| c.span == sink.span()) {
                    flows.push(TaintFlow {
                        source: source.clone(),
                        sink: sink.clone(),
                        flow_kind: FlowKind::Direct,
                    });
                    continue;
                }

                // LEVEL 2: Transitive flow (one hop)
                let refs = sa.references_to(sym_id);
                for r in &refs {
                    for decl in &sa.declarations {
                        if let Some(init_span) = decl.initializer_span {
                            if span_contains(init_span, r.span) {
                                let transitive_calls = sa.symbol_flows_to_call(decl.symbol_id);
                                if transitive_calls.iter().any(|c| c.span == sink.span()) {
                                    flows.push(TaintFlow {
                                        source: source.clone(),
                                        sink: sink.clone(),
                                        flow_kind: FlowKind::Transitive {
                                            through: vec![decl.name.clone()],
                                        },
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // LEVEL 3: Same-scope fallback (weakest signal)
            if sa.same_scope_or_nested(source_scope, sink.scope_id()) {
                flows.push(TaintFlow {
                    source: source.clone(),
                    sink: sink.clone(),
                    flow_kind: FlowKind::SameScope,
                });
            }
        }
    }

    flows
}

/// Calculate Shannon entropy of byte data
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

fn span_contains(outer: (u32, u32), inner: (u32, u32)) -> bool {
    outer.0 <= inner.0 && inner.1 <= outer.1
}

#[cfg(test)]
#[cfg(feature = "semantic")]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_entropy_uniform() {
        // All same byte = 0 entropy
        let entropy = calculate_entropy(&[0x41, 0x41, 0x41, 0x41]);
        assert!((entropy - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_calculate_entropy_varied() {
        // Different bytes = higher entropy
        let entropy = calculate_entropy(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert!(entropy > 2.5);
    }

    #[test]
    fn test_calculate_entropy_high() {
        // Random-looking data = high entropy
        let data: Vec<u8> = (0..=255).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.9);
    }
}
