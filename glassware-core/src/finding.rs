//! Finding Types
//!
//! This module defines the data structures for representing security findings.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

pub use crate::decoder::{DecodedPayload, PayloadClass};

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum Severity {
    /// Low severity finding - minimal security concern
    Low,
    /// Medium severity finding - moderate security concern
    Medium,
    /// High severity finding - significant security concern
    High,
    /// Critical severity finding - immediate attention required
    Critical,
    /// Informational finding - heuristic pattern match
    Info,
}

impl Severity {
    /// Get the string representation of the severity level
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
            Severity::Info => "info",
        }
    }

    /// Parse a severity level from a string (case-insensitive)
    pub fn from_str_val(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "info" => Severity::Info,
            _ => Severity::Low,
        }
    }
}

impl FromStr for Severity {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_str_val(s))
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Category of detected attack
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DetectionCategory {
    /// Invisible character (zero-width, variation selectors)
    InvisibleCharacter,
    /// Homoglyph/confusable character attack
    Homoglyph,
    /// Bidirectional text override attack
    BidirectionalOverride,
    /// Unicode tag character injection
    UnicodeTag,
    /// Unicode normalization attack
    NormalizationAttack,
    /// Glassware-specific attack pattern
    GlasswarePattern,
    /// Emoji-based obfuscation
    EmojiObfuscation,
    /// Dense run of VS codepoints encoding hidden data
    SteganoPayload,
    /// Visible code matching GlassWare decoder pattern
    DecoderFunction,
    /// VS codepoints after pipe delimiter (npm variant)
    PipeDelimiterStego,
    /// High-entropy blob combined with dynamic code execution
    EncryptedPayload,
    /// HTTP header C2 pattern with decryption and execution
    HeaderC2,
    /// Hardcoded cryptographic key used for decryption to exec
    HardcodedKeyDecryption,
    /// Hand-rolled RC4-like cipher pattern with dynamic execution
    Rc4Pattern,
    /// Unknown category
    Unknown,
}

impl DetectionCategory {
    /// Get the string representation of the category
    pub fn as_str(&self) -> &'static str {
        match self {
            DetectionCategory::InvisibleCharacter => "invisible_character",
            DetectionCategory::Homoglyph => "homoglyph",
            DetectionCategory::BidirectionalOverride => "bidirectional_override",
            DetectionCategory::UnicodeTag => "unicode_tag",
            DetectionCategory::NormalizationAttack => "normalization_attack",
            DetectionCategory::GlasswarePattern => "glassware_pattern",
            DetectionCategory::EmojiObfuscation => "emoji_obfuscation",
            DetectionCategory::SteganoPayload => "stegano_payload",
            DetectionCategory::DecoderFunction => "decoder_function",
            DetectionCategory::PipeDelimiterStego => "pipe_delimiter_stego",
            DetectionCategory::EncryptedPayload => "encrypted_payload",
            DetectionCategory::HeaderC2 => "header_c2",
            DetectionCategory::HardcodedKeyDecryption => "hardcoded_key_decryption",
            DetectionCategory::Rc4Pattern => "rc4_pattern",
            DetectionCategory::Unknown => "unknown",
        }
    }
}

/// Represents a source location in a file
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SourceLocation {
    /// File path where the finding was detected
    pub file: String,
    /// Line number (1-indexed)
    pub line: usize,
    /// Column number (1-indexed)
    pub column: usize,
    /// Byte offset in the file (if available)
    pub byte_offset: Option<usize>,
}

impl SourceLocation {
    /// Create a new source location
    pub fn new(file: &str, line: usize, column: usize) -> Self {
        Self {
            file: file.to_string(),
            line,
            column,
            byte_offset: None,
        }
    }
}

/// A security finding
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Finding {
    /// File path where the finding was detected
    pub file: String,
    /// Line number (1-indexed)
    pub line: usize,
    /// Column number (1-indexed)
    pub column: usize,
    /// Unicode code point value (0 for non-Unicode detections)
    pub code_point: u32,
    /// The character itself (may be empty for invisible chars)
    pub character: String,
    /// Raw bytes of the invisible sequence (for decoded payload display)
    pub raw_bytes: Option<String>,
    /// Category of the attack
    pub category: DetectionCategory,
    /// Severity level
    pub severity: Severity,
    /// Human-readable description
    pub description: String,
    /// Remediation guidance
    pub remediation: String,
    /// CWE ID if applicable (e.g., "CWE-172")
    pub cwe_id: Option<String>,
    /// References to research/advisories
    pub references: Vec<String>,
    /// Optional snippet of surrounding context
    pub context: Option<String>,
    /// Decoded steganographic payload (if applicable)
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub decoded_payload: Option<DecodedPayload>,
    /// Confidence score (0.0-1.0) for heuristic detections
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub confidence: Option<f64>,
}

impl Finding {
    /// Create a new finding with basic information
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        file: &str,
        line: usize,
        column: usize,
        code_point: u32,
        character: char,
        category: DetectionCategory,
        severity: Severity,
        description: &str,
        remediation: &str,
    ) -> Self {
        Self {
            file: file.to_string(),
            line,
            column,
            code_point,
            character: character.to_string(),
            raw_bytes: None,
            category,
            severity,
            description: description.to_string(),
            remediation: remediation.to_string(),
            cwe_id: None,
            references: Vec::new(),
            context: None,
            decoded_payload: None,
            confidence: None,
        }
    }

    /// Set the CWE ID for this finding
    pub fn with_cwe_id(mut self, cwe_id: &str) -> Self {
        self.cwe_id = Some(cwe_id.to_string());
        self
    }

    /// Add a reference URL to this finding
    pub fn with_reference(mut self, url: &str) -> Self {
        self.references.push(url.to_string());
        self
    }

    /// Set the context snippet for this finding
    pub fn with_context(mut self, context: &str) -> Self {
        self.context = Some(context.to_string());
        self
    }

    /// Set the raw bytes for this finding
    pub fn with_raw_bytes(mut self, bytes: &str) -> Self {
        self.raw_bytes = Some(bytes.to_string());
        self
    }

    /// Set the decoded payload for this finding
    pub fn with_decoded_payload(mut self, payload: DecodedPayload) -> Self {
        self.decoded_payload = Some(payload);
        self
    }

    /// Set the confidence score for this finding
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = Some(confidence);
        self
    }

    /// Get the source location of this finding
    pub fn location(&self) -> SourceLocation {
        SourceLocation::new(&self.file, self.line, self.column)
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}:{}:{} - U+{:04X} ({}) - {}",
            self.severity.as_str().to_uppercase(),
            self.file,
            self.line,
            self.column,
            self.code_point,
            self.category.as_str(),
            self.description
        )
    }
}
