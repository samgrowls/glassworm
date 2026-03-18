//! Unicode Scanner Configuration
//!
//! This module provides configuration options for Unicode attack detection.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Unicode scanner configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UnicodeConfig {
    /// Enable Unicode scanning
    pub enabled: bool,

    /// Sensitivity level: low, medium, high, critical
    pub sensitivity: SensitivityLevel,

    /// Enable/disable individual detectors
    pub detectors: DetectorConfig,

    /// File patterns to include
    pub include_patterns: Vec<String>,

    /// File patterns to exclude
    pub exclude_patterns: Vec<String>,

    /// Allowlist for legitimate i18n usage
    pub allowlist: AllowlistConfig,
}

/// Sensitivity levels for Unicode detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum SensitivityLevel {
    /// Report all findings including low-severity issues
    Low,
    /// Report medium and higher severity findings
    Medium,
    /// Report high and critical severity findings (default)
    #[default]
    High,
    /// Report only critical severity findings
    Critical,
}

impl SensitivityLevel {
    /// Get the string representation of the sensitivity level
    pub fn as_str(&self) -> &'static str {
        match self {
            SensitivityLevel::Low => "low",
            SensitivityLevel::Medium => "medium",
            SensitivityLevel::High => "high",
            SensitivityLevel::Critical => "critical",
        }
    }

    /// Parse a sensitivity level from a string (case-insensitive)
    pub fn from_str_val(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => SensitivityLevel::Critical,
            "high" => SensitivityLevel::High,
            "medium" => SensitivityLevel::Medium,
            _ => SensitivityLevel::Low,
        }
    }
}

/// Configuration for individual detectors
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DetectorConfig {
    /// Detect invisible characters (zero-width, variation selectors)
    pub invisible_chars: bool,

    /// Detect homoglyph/confusable characters
    pub homoglyphs: bool,

    /// Detect bidirectional overrides
    pub bidirectional: bool,

    /// Detect Unicode tags
    pub unicode_tags: bool,

    /// Detect Glassware-specific patterns
    pub glassware: bool,

    /// Detect normalization attacks
    pub normalization: bool,

    /// Detect emoji obfuscation
    pub emoji_obfuscation: bool,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            invisible_chars: true,
            homoglyphs: true,
            bidirectional: true,
            unicode_tags: true,
            glassware: true,
            normalization: false,
            emoji_obfuscation: false,
        }
    }
}

/// Allowlist configuration for legitimate i18n usage
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AllowlistConfig {
    /// Files to always allow (e.g., i18n resource files)
    pub files: HashSet<String>,

    /// Patterns to allow (e.g., emoji with variation selectors)
    pub patterns: HashSet<String>,

    /// Allow emoji variation selectors
    pub allow_emoji_variants: bool,

    /// Allow CJK character variants
    pub allow_cjk_variants: bool,
}

/// Performance tuning configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PerformanceConfig {
    /// Maximum file size to scan (bytes)
    pub max_file_size: u64,

    /// Skip binary files
    pub skip_binary: bool,

    /// Parallel scanning enabled
    pub parallel: bool,
}

impl Default for PerformanceConfig {
    /// Create default performance settings (10MB max, skip binary files, parallel enabled)
    fn default() -> Self {
        Self {
            max_file_size: 10 * 1024 * 1024, // 10MB
            skip_binary: true,
            parallel: true,
        }
    }
}

impl Default for UnicodeConfig {
    /// Create default configuration (enabled, high sensitivity, all detectors on)
    fn default() -> Self {
        Self {
            enabled: true,
            sensitivity: SensitivityLevel::default(),
            detectors: DetectorConfig::default(),
            include_patterns: vec![],
            exclude_patterns: vec![".git".to_string(), "node_modules".to_string()],
            allowlist: AllowlistConfig::default(),
        }
    }
}

impl UnicodeConfig {
    /// Create config for i18n projects (more permissive)
    pub fn for_i18n_project() -> Self {
        Self {
            sensitivity: SensitivityLevel::Medium,
            allowlist: AllowlistConfig {
                allow_emoji_variants: true,
                allow_cjk_variants: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Create config for high-security projects (stricter)
    pub fn for_high_security() -> Self {
        Self {
            sensitivity: SensitivityLevel::Critical,
            detectors: DetectorConfig {
                normalization: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }
}
