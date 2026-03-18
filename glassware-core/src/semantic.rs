//! Semantic Analysis Module
//!
//! Wraps OXC's parse → semantic pipeline into a clean interface for JS/TS analysis.
//! Extracts semantic information into owned data structures to avoid lifetime issues.

#[cfg(feature = "semantic")]
use oxc_allocator::Allocator;
#[cfg(feature = "semantic")]
use oxc_ast::ast::{CallExpression, Expression, VariableDeclarationKind};
#[cfg(feature = "semantic")]
use oxc_ast::AstKind;
#[cfg(feature = "semantic")]
use oxc_index::Idx;
#[cfg(feature = "semantic")]
use oxc_parser::Parser;
#[cfg(feature = "semantic")]
use oxc_semantic::SemanticBuilder;
#[cfg(feature = "semantic")]
use oxc_span::{GetSpan, SourceType};
use std::collections::HashMap;
use std::path::Path;

/// Scope information including span
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScopeInfo {
    pub scope_id: u32,
    pub parent_id: Option<u32>,
    pub span: (u32, u32),
}

/// Pre-extracted semantic information, fully owned (no OXC lifetimes).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SemanticAnalysis {
    pub string_literals: Vec<StringLiteralInfo>,
    pub call_sites: Vec<CallSite>,
    pub declarations: Vec<Declaration>,
    pub references: Vec<ResolvedReference>,
    pub scopes: Vec<ScopeInfo>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StringLiteralInfo {
    pub value: String,
    pub span: (u32, u32),
    pub scope_id: u32,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CallSite {
    pub callee: String,
    pub callee_chain: Vec<String>,
    pub arg_spans: Vec<(u32, u32)>,
    pub span: (u32, u32),
    pub scope_id: u32,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Declaration {
    pub name: String,
    pub kind: DeclKind,
    pub initializer_span: Option<(u32, u32)>,
    pub scope_id: u32,
    pub symbol_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DeclKind {
    Let,
    Const,
    Var,
    Function,
    Parameter,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResolvedReference {
    pub name: String,
    pub span: (u32, u32),
    pub scope_id: u32,
    pub resolved_symbol_id: Option<u32>,
}

#[cfg(feature = "semantic")]
pub fn build_semantic(source: &str, path: &Path) -> Option<SemanticAnalysis> {
    let source_type = SourceType::from_path(path).ok()?;

    if !source_type.is_javascript() && !source_type.is_typescript() {
        return None;
    }

    let allocator = Allocator::default();
    let parser_ret = Parser::new(&allocator, source, source_type).parse();

    if !parser_ret.errors.is_empty() {
        return None;
    }

    let semantic_ret = SemanticBuilder::new()
        .with_cfg(true)
        .build(&parser_ret.program);

    let semantic = semantic_ret.semantic;
    let mut analysis = SemanticAnalysis::default();

    // Extract scope tree - iterate through all scope IDs
    // Note: Getting exact spans for scopes requires walking the AST and matching
    // each scope to its creating node. For now, we use placeholder spans and
    // refine based on the references/declarations we find.
    let mut scope_spans: HashMap<u32, (u32, u32)> = HashMap::new();

    for i in 0..semantic.scopes().len() {
        let scope_id = oxc_index::Idx::from_usize(i);
        let parent_id = semantic.scopes().get_parent_id(scope_id);

        // Initialize with full file span, will be refined below
        scope_spans.insert(scope_id.index() as u32, (0, source.len() as u32));

        analysis.scopes.push(ScopeInfo {
            scope_id: scope_id.index() as u32,
            parent_id: parent_id.map(|id| id.index() as u32),
            span: (0, source.len() as u32),
        });
    }

    // Walk AST to refine scope spans and extract information
    let nodes = semantic.nodes();
    let mut symbol_counter: u32 = 0;

    for node in nodes.iter() {
        let scope_id = node.scope_id().index() as u32;
        let node_span = (node.span().start, node.span().end);

        // Refine scope span to be the smallest containing all its nodes
        if let Some(scope) = analysis.scopes.iter_mut().find(|s| s.scope_id == scope_id) {
            scope.span.0 = scope.span.0.min(node_span.0);
            scope.span.1 = scope.span.1.max(node_span.1);
        }

        match node.kind() {
            AstKind::StringLiteral(lit) => {
                analysis.string_literals.push(StringLiteralInfo {
                    value: lit.value.to_string(),
                    span: (lit.span.start, lit.span.end),
                    scope_id,
                });
            }
            AstKind::CallExpression(call) => {
                if let Some(call_site) = extract_call_site(call, scope_id) {
                    analysis.call_sites.push(call_site);
                }
            }
            AstKind::VariableDeclarator(decl) => {
                if let Some(name_atom) = decl.id.get_identifier() {
                    let init_span = decl
                        .init
                        .as_ref()
                        .map(|init| (init.span().start, init.span().end));
                    analysis.declarations.push(Declaration {
                        name: name_atom.to_string(),
                        kind: match decl.kind {
                            VariableDeclarationKind::Let => DeclKind::Let,
                            VariableDeclarationKind::Const => DeclKind::Const,
                            VariableDeclarationKind::Var => DeclKind::Var,
                            VariableDeclarationKind::Using
                            | VariableDeclarationKind::AwaitUsing => DeclKind::Const,
                        },
                        initializer_span: init_span,
                        scope_id,
                        symbol_id: symbol_counter,
                    });
                    symbol_counter += 1;
                }
            }
            AstKind::IdentifierReference(id_ref) => {
                // For references, try to find matching declaration by name and scope
                let resolved_symbol_id =
                    find_matching_declaration(&analysis, id_ref.name.as_str(), scope_id);

                analysis.references.push(ResolvedReference {
                    name: id_ref.name.to_string(),
                    span: (id_ref.span.start, id_ref.span.end),
                    scope_id,
                    resolved_symbol_id,
                });
            }
            _ => {}
        }
    }

    Some(analysis)
}

/// Find a matching declaration by name and scope (simple heuristic)
fn find_matching_declaration(
    analysis: &SemanticAnalysis,
    name: &str,
    scope_id: u32,
) -> Option<u32> {
    analysis
        .declarations
        .iter()
        .find(|d| d.name == name && d.scope_id == scope_id)
        .map(|d| d.symbol_id)
}

#[cfg(feature = "semantic")]
fn extract_call_site(call: &CallExpression, scope_id: u32) -> Option<CallSite> {
    let (callee, callee_chain) = match &call.callee {
        Expression::Identifier(id) => (id.name.to_string(), vec![]),
        Expression::StaticMemberExpression(member) => {
            let mut chain = vec![];
            let current = member.as_ref();
            chain.push(current.property.name.to_string());

            let mut obj = &current.object;
            while let Expression::StaticMemberExpression(m) = obj {
                chain.push(m.property.name.to_string());
                obj = &m.object;
            }

            if let Expression::Identifier(id) = obj {
                chain.push(id.name.to_string());
            }

            chain.reverse();
            let callee_name = chain.last()?.clone();
            (callee_name, chain.clone())
        }
        Expression::ComputedMemberExpression(_) => {
            ("computed".to_string(), vec!["computed".to_string()])
        }
        _ => return None,
    };

    let arg_spans: Vec<(u32, u32)> = call
        .arguments
        .iter()
        .map(|arg| (arg.span().start, arg.span().end))
        .collect();

    Some(CallSite {
        callee,
        callee_chain,
        arg_spans,
        span: (call.span.start, call.span.end),
        scope_id,
    })
}

#[cfg(not(feature = "semantic"))]
pub fn build_semantic(_source: &str, _path: &Path) -> Option<SemanticAnalysis> {
    None
}

impl SemanticAnalysis {
    /// Check if two scopes are the same or nested
    pub fn same_scope_or_nested(&self, scope_a: u32, scope_b: u32) -> bool {
        if scope_a == scope_b {
            return true;
        }

        // Walk up from scope_a to see if we reach scope_b
        let mut current = Some(scope_a);
        while let Some(id) = current {
            if id == scope_b {
                return true;
            }
            current = self
                .scopes
                .iter()
                .find(|s| s.scope_id == id)
                .and_then(|s| s.parent_id);
        }

        // Walk up from scope_b to see if we reach scope_a
        current = Some(scope_b);
        while let Some(id) = current {
            if id == scope_a {
                return true;
            }
            current = self
                .scopes
                .iter()
                .find(|s| s.scope_id == id)
                .and_then(|s| s.parent_id);
        }

        false
    }

    /// Find the most specific (innermost) scope containing a byte offset
    pub fn scope_at_offset(&self, offset: u32) -> Option<u32> {
        self.scopes
            .iter()
            .filter(|s| s.span.0 <= offset && offset <= s.span.1)
            .min_by_key(|s| s.span.1 - s.span.0)
            .map(|s| s.scope_id)
    }

    /// Check if the expression at `span` is or resolves to a string literal.
    /// Handles: direct string literals, and identifiers that resolve to
    /// a declaration initialized with a string literal (one hop).
    pub fn resolves_to_string_literal(&self, span: (u32, u32)) -> Option<&StringLiteralInfo> {
        // DIRECT: Is there a string literal whose span falls within this span?
        if let Some(lit) = self
            .string_literals
            .iter()
            .find(|s| span_contains(span, s.span))
        {
            return Some(lit);
        }

        // ONE-HOP: Is there an identifier reference in this span that resolves
        // to a declaration initialized with a string literal?
        for reference in &self.references {
            if span_contains(span, reference.span) {
                if let Some(sym_id) = reference.resolved_symbol_id {
                    if let Some(decl) = self.declarations.iter().find(|d| d.symbol_id == sym_id) {
                        if let Some(init_span) = decl.initializer_span {
                            if let Some(lit) = self
                                .string_literals
                                .iter()
                                .find(|s| span_contains(init_span, s.span))
                            {
                                return Some(lit);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    pub fn references_to(&self, symbol_id: u32) -> Vec<&ResolvedReference> {
        self.references
            .iter()
            .filter(|r| r.resolved_symbol_id == Some(symbol_id))
            .collect()
    }

    pub fn symbol_flows_to_call(&self, symbol_id: u32) -> Vec<&CallSite> {
        let refs = self.references_to(symbol_id);
        let ref_spans: Vec<(u32, u32)> = refs.iter().map(|r| r.span).collect();

        self.call_sites
            .iter()
            .filter(|call| {
                call.arg_spans.iter().any(|arg_span| {
                    ref_spans
                        .iter()
                        .any(|ref_span| span_contains(*arg_span, *ref_span))
                })
            })
            .collect()
    }

    pub fn find_declaration_for_span(&self, span: (u32, u32)) -> Option<&Declaration> {
        self.declarations.iter().find(|decl| {
            decl.initializer_span
                .map(|init| span_contains(init, span))
                .unwrap_or(false)
        })
    }
}

fn span_contains(outer: (u32, u32), inner: (u32, u32)) -> bool {
    outer.0 <= inner.0 && inner.1 <= outer.1
}

#[cfg(test)]
#[cfg(feature = "semantic")]
mod tests {
    use super::*;

    #[test]
    fn test_build_semantic_simple() {
        let source = r#"
            const x = "hello";
            console.log(x);
        "#;
        let path = Path::new("test.js");
        let analysis = build_semantic(source, path);

        assert!(analysis.is_some());
        let analysis = analysis.unwrap();
        assert!(!analysis.string_literals.is_empty());
        assert!(!analysis.call_sites.is_empty());
    }

    #[test]
    fn test_call_site_extraction() {
        let source = r#"
            eval(payload);
        "#;
        let path = Path::new("test.js");
        let analysis = build_semantic(source, path).unwrap();

        let eval_calls: Vec<_> = analysis
            .call_sites
            .iter()
            .filter(|c| c.callee == "eval")
            .collect();
        assert!(!eval_calls.is_empty());
    }
}
