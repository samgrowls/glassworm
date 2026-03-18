//! Detector Trait
//!
//! Defines the interface for detection modules that scan file content
//! for suspicious patterns.

use crate::config::UnicodeConfig;
use crate::finding::Finding;
use std::path::Path;

/// A detection module that scans file content for suspicious patterns.
///
/// Each detector targets a specific class of attack technique.
/// The engine runs all registered detectors against each file.
pub trait Detector: Send + Sync {
    /// Human-readable name (e.g. "unicode", "encrypted-loader").
    fn name(&self) -> &str;

    /// Scan file content. Return findings, or empty vec if clean.
    /// `path` is provided for metadata (file extension, path context).
    /// `content` is the full file content as a string.
    /// `config` provides sensitivity and detector-specific settings.
    fn scan(&self, path: &Path, content: &str, config: &UnicodeConfig) -> Vec<Finding>;
}

/// Detector that operates on parsed semantic information (JS/TS only).
///
/// This trait is for detectors that use OXC semantic analysis
/// for more accurate flow-based detection.
#[cfg(feature = "semantic")]
pub trait SemanticDetector: Send + Sync {
    /// Unique identifier matching a GW rule (e.g., "GW005")
    fn id(&self) -> &str;

    /// Run detection using semantic analysis + taint flows.
    /// `sources` and `sinks` are pre-computed taint sources and sinks.
    fn detect_semantic(
        &self,
        source_code: &str,
        path: &Path,
        flows: &[crate::taint::TaintFlow],
        sources: &[crate::taint::TaintSource],
        sinks: &[crate::taint::TaintSink],
    ) -> Vec<Finding>;
}
