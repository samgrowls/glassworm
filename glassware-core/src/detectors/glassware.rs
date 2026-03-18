//! Glassware-Specific Detector
//!
//! Specialized detector for Glassware attack patterns including:
//! - Dense runs of VS codepoints (steganographic payloads)
//! - Decoder function patterns (codePointAt + VS constants)
//! - Pipe delimiter patterns (npm variant)
//!
//! Note: This detector requires the `regex` feature for pattern detection.

#[cfg(feature = "regex")]
use regex::Regex;

use crate::config::UnicodeConfig;
use crate::decoder::{decode_vs_stego, find_vs_runs, is_vs_codepoint};
use crate::finding::{DetectionCategory, Finding, Severity};

/// Minimum run length of VS codepoints to consider as stego payload
const DEFAULT_MIN_RUN_LENGTH: usize = 16;

/// Detector for Glassware attack patterns
pub struct GlasswareDetector {
    #[cfg(feature = "regex")]
    decoder_patterns: Vec<Regex>,
    #[cfg(feature = "regex")]
    eval_patterns: Vec<Regex>,
    #[cfg(feature = "regex")]
    encoding_patterns: Vec<Regex>,
    #[cfg(feature = "regex")]
    #[allow(dead_code)]
    config: UnicodeConfig,
    #[cfg(not(feature = "regex"))]
    #[allow(dead_code)]
    config: UnicodeConfig,
    min_run_length: usize,
}

#[cfg(feature = "regex")]
lazy_static::lazy_static! {
    static ref DECODER_PATTERNS: Vec<Regex> = vec![
        // codePointAt with VS constants
        Regex::new(r"codePointAt\s*\(\s*0\s*\)").unwrap(),
        Regex::new(r"codePointAt\s*\([^)]*0x[Ff][Ee]00").unwrap(),
        Regex::new(r"codePointAt\s*\([^)]*0x[Ee]0100").unwrap(),
        // String.fromCharCode/fromCodePoint
        Regex::new(r"String\.fromCharCode\s*\(").unwrap(),
        Regex::new(r"String\.fromCodePoint\s*\(").unwrap(),
        // Filter patterns
        Regex::new(r"\.filter\s*\(\s*c\s*=>\s*c\s*!==\s*null\s*\)").unwrap(),
    ];

    static ref EVAL_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"\beval\s*\(").unwrap(),
        Regex::new(r"\bFunction\s*\(").unwrap(),
        Regex::new(r"new\s+Function\s*\(").unwrap(),
    ];

    static ref ENCODING_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"Buffer\.from\s*\([^,]+,\s*hex\s*\)").unwrap(),
        Regex::new(r"Buffer\.from\s*\([^,]+,\s*base64\s*\)").unwrap(),
        Regex::new(r"\batob\s*\(").unwrap(),
        Regex::new(r"\bbtoa\s*\(").unwrap(),
    ];

    // Pattern for detecting VS constants in visible code
    static ref VS_CONSTANT_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"0x[Ff][Ee]00").unwrap(),  // 0xFE00
        Regex::new(r"0x[Ee]0100").unwrap(),    // 0xE0100
        Regex::new(r"\\u\{[Ff][Ee]0[0-9A-Fa-f]\}").unwrap(),  // \u{FE0x}
        Regex::new(r"\\u\{[Ee]01[0-9A-Fa-f]{2}\}").unwrap(),  // \u{E01xx}
    ];
}

impl GlasswareDetector {
    pub fn new(config: UnicodeConfig) -> Self {
        Self {
            #[cfg(feature = "regex")]
            decoder_patterns: DECODER_PATTERNS.clone(),
            #[cfg(feature = "regex")]
            eval_patterns: EVAL_PATTERNS.clone(),
            #[cfg(feature = "regex")]
            encoding_patterns: ENCODING_PATTERNS.clone(),
            config,
            min_run_length: DEFAULT_MIN_RUN_LENGTH,
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(UnicodeConfig::default())
    }

    /// Set minimum run length for VS stego detection
    pub fn with_min_run_length(mut self, min_run_length: usize) -> Self {
        self.min_run_length = min_run_length;
        self
    }

    #[cfg(feature = "regex")]
    pub fn detect(&self, content: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Detect dense VS codepoint runs (steganographic payloads)
        findings.extend(self.detect_stego_runs(content, file_path));

        // 2. Detect pipe delimiter pattern (npm variant)
        findings.extend(self.detect_pipe_delimiter(content, file_path));

        // 3. Detect decoder function patterns
        findings.extend(self.detect_decoder_functions(content, file_path));

        // 4. Detect Glassware patterns (original functionality)
        findings.extend(self.detect_glassware_patterns(content, file_path));

        findings
    }

    #[cfg(not(feature = "regex"))]
    pub fn detect(&self, content: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(self.detect_stego_runs(content, file_path));
        findings
    }

    /// Detect dense runs of VS codepoints
    fn detect_stego_runs(&self, content: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let runs = find_vs_runs(content, self.min_run_length);

        for (start_offset, end_offset, codepoint_count) in runs {
            // Extract the VS run
            let vs_run = &content[start_offset..end_offset];

            // Calculate line/column for the start of the run
            let (line, column) = self.offset_to_line_col(content, start_offset);

            // Try to decode the payload
            let decoded = decode_vs_stego(vs_run);

            let (description, severity, decoded_payload) = if let Some(payload) = decoded {
                let class_desc = payload.payload_class.description();
                (
                    format!(
                        "Steganographic payload detected: {} VS codepoints decode to {} bytes (entropy: {:.2}, {})",
                        codepoint_count,
                        payload.bytes.len(),
                        payload.entropy,
                        class_desc
                    ),
                    Severity::Critical,
                    Some(payload),
                )
            } else {
                (
                    format!(
                        "Dense run of {} Variation Selector codepoints detected (potential steganographic payload)",
                        codepoint_count
                    ),
                    Severity::High,
                    None,
                )
            };

            let finding = Finding {
                file: file_path.to_string(),
                line,
                column,
                code_point: 0,
                character: String::new(),
                raw_bytes: None,
                category: DetectionCategory::SteganoPayload,
                severity,
                description,
                remediation: "Review this file for hidden steganographic payloads. \
                             The Variation Selector codepoints may encode malicious code \
                             that is decoded and executed at runtime. Use the decoded payload \
                             preview to understand what's hidden."
                    .to_string(),
                cwe_id: Some("CWE-506".to_string()), // Embedded Malicious Code
                references: vec![
                    "https://www.aikido.dev/blog/glassware-returns-unicode-attack-github-npm-vscode".to_string(),
                ],
                context: self.get_context(content, start_offset, end_offset),
                decoded_payload,
                confidence: None,
            };

            findings.push(finding);
        }

        findings
    }

    /// Detect VS codepoints after pipe delimiter (npm variant)
    fn detect_pipe_delimiter(&self, content: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let chars: Vec<(usize, char)> = content.char_indices().collect();

        for i in 0..chars.len() {
            if chars[i].1 == '|' {
                // Check if next char is a VS codepoint
                if i + 1 < chars.len() && is_vs_codepoint(chars[i + 1].1) {
                    // Count how many VS codepoints follow
                    let mut vs_count = 0;
                    let mut j = i + 1;
                    while j < chars.len() && is_vs_codepoint(chars[j].1) {
                        vs_count += 1;
                        j += 1;
                    }

                    if vs_count >= 4 {
                        let (line, column) = self.offset_to_line_col(content, chars[i].0);

                        // Extract the VS run after the pipe
                        let vs_start = chars[i + 1].0;
                        let vs_end = if j < chars.len() {
                            chars[j].0
                        } else {
                            content.len()
                        };
                        let vs_run = &content[vs_start..vs_end];

                        let decoded = decode_vs_stego(vs_run);

                        let finding = Finding {
                            file: file_path.to_string(),
                            line,
                            column,
                            code_point: 0,
                            character: String::new(),
                            raw_bytes: None,
                            category: DetectionCategory::PipeDelimiterStego,
                            severity: Severity::Critical,
                            description: format!(
                                "Pipe delimiter steganography detected: {} VS codepoints after '|' (npm variant)",
                                vs_count
                            ),
                            remediation: "This is the npm GlassWare variant. VS codepoints after \
                                         pipe delimiters encode hidden payloads. Review the decoded content."
                                .to_string(),
                            cwe_id: Some("CWE-506".to_string()),
                            references: vec![
                                "https://www.aikido.dev/blog/glassware-returns-unicode-attack-github-npm-vscode".to_string(),
                            ],
                            context: self.get_context(content, chars[i].0, vs_end),
                            decoded_payload: decoded,
                            confidence: None,
                        };

                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }

    /// Detect decoder function patterns in visible code
    #[cfg(feature = "regex")]
    fn detect_decoder_functions(&self, content: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            // Check for VS constant patterns (indicates decoder code)
            for pattern in VS_CONSTANT_PATTERNS.iter() {
                if let Some(m) = pattern.find(line) {
                    // Also check if codePointAt is nearby
                    let has_codepointat = line.contains("codePointAt");

                    if has_codepointat {
                        let finding = Finding {
                            file: file_path.to_string(),
                            line: line_num + 1,
                            column: m.start() + 1,
                            code_point: 0,
                            character: String::new(),
                            raw_bytes: None,
                            category: DetectionCategory::DecoderFunction,
                            severity: Severity::High,
                            description: "GlassWare-style decoder function detected: codePointAt \
                                         with Variation Selector range constants (0xFE00/0xE0100)"
                                .to_string(),
                            remediation: "This file contains decoder logic for VS steganographic \
                                         payloads. Review the file that contains the encoded payload."
                                .to_string(),
                            cwe_id: Some("CWE-506".to_string()),
                            references: vec![
                                "https://www.aikido.dev/blog/glassware-returns-unicode-attack-github-npm-vscode".to_string(),
                            ],
                            context: self.get_line_context(line),
                            decoded_payload: None,
                            confidence: None,
                        };

                        findings.push(finding);
                        break; // One finding per line
                    }
                }
            }
        }

        findings
    }

    #[cfg(not(feature = "regex"))]
    fn detect_decoder_functions(&self, _content: &str, _file_path: &str) -> Vec<Finding> {
        Vec::new()
    }

    /// Detect original GlassWare patterns
    #[cfg(feature = "regex")]
    fn detect_glassware_patterns(&self, content: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut indicators = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.decoder_patterns {
                if let Some(m) = pattern.find(line) {
                    indicators.push((line_num, m.start(), "decoder_pattern"));
                }
            }

            for pattern in &self.eval_patterns {
                if let Some(m) = pattern.find(line) {
                    indicators.push((line_num, m.start(), "eval_pattern"));
                }
            }

            for pattern in &self.encoding_patterns {
                if let Some(m) = pattern.find(line) {
                    indicators.push((line_num, m.start(), "encoding_pattern"));
                }
            }
        }

        // Only report if we have multiple indicators (reduces FPs)
        if indicators.len() >= 2 {
            let confidence = Self::calculate_confidence(indicators.len());

            for (line_num, col, indicator_type) in indicators {
                let severity = if confidence >= 0.8 {
                    Severity::Critical
                } else if confidence >= 0.6 {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let finding = Finding {
                    file: file_path.to_string(),
                    line: line_num + 1,
                    column: col + 1,
                    code_point: 0,
                    character: String::new(),
                    raw_bytes: None,
                    category: DetectionCategory::GlasswarePattern,
                    severity,
                    description: format!(
                        "GlassWare attack pattern detected: {} (confidence: {:.0}%)",
                        indicator_type,
                        confidence * 100.0
                    ),
                    remediation: Self::get_remediation(confidence),
                    cwe_id: Some("CWE-956".to_string()),
                    references: vec![
                        "https://www.aikido.dev/blog/glassware-returns-unicode-attack-github-npm-vscode".to_string(),
                    ],
                    context: Some(content.lines().nth(line_num).unwrap_or("").to_string()),
                    decoded_payload: None,
                    confidence: None,
                };

                findings.push(finding);
            }
        }

        findings
    }

    #[cfg(not(feature = "regex"))]
    fn detect_glassware_patterns(&self, _content: &str, _file_path: &str) -> Vec<Finding> {
        Vec::new()
    }

    #[cfg(feature = "regex")]
    fn calculate_confidence(indicator_count: usize) -> f32 {
        let base = (indicator_count as f32 * 0.2).min(0.8);
        let count_bonus = match indicator_count {
            2..=3 => 0.05,
            4..=5 => 0.1,
            _ => 0.15,
        };
        (base + count_bonus).min(1.0)
    }

    #[cfg(not(feature = "regex"))]
    fn calculate_confidence(_indicator_count: usize) -> f32 {
        0.0
    }

    #[cfg(feature = "regex")]
    fn get_remediation(confidence: f32) -> String {
        if confidence >= 0.8 {
            "CRITICAL: This code exhibits strong GlassWare attack characteristics.".to_string()
        } else if confidence >= 0.6 {
            "HIGH: This code shows patterns consistent with GlassWare-style attacks.".to_string()
        } else {
            "MEDIUM: Some patterns associated with GlassWare attacks were detected.".to_string()
        }
    }

    /// Convert byte offset to line/column
    fn offset_to_line_col(&self, content: &str, offset: usize) -> (usize, usize) {
        let mut line = 1;
        let mut col = 1;

        for (i, ch) in content.char_indices() {
            if i >= offset {
                break;
            }
            if ch == '\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
        }

        (line, col)
    }

    /// Get context around a byte range
    fn get_context(&self, content: &str, start: usize, end: usize) -> Option<String> {
        // Get surrounding context (up to 100 chars before and after)
        let context_start = start.saturating_sub(100);
        let context_end = (end + 100).min(content.len());

        let prefix = if context_start > 0 { "..." } else { "" };
        let suffix = if context_end < content.len() {
            "..."
        } else {
            ""
        };

        Some(format!(
            "{}{}{}{}",
            prefix,
            &content[context_start..start],
            &content[end..context_end],
            suffix
        ))
    }

    /// Get line context
    fn get_line_context(&self, line: &str) -> Option<String> {
        // Truncate long lines
        if line.len() > 200 {
            Some(format!("{}...", &line[..200]))
        } else {
            Some(line.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::encode_vs_stego;

    #[test]
    #[cfg(feature = "regex")]
    fn test_stego_run_detection() {
        let detector = GlasswareDetector::with_default_config();

        // Create a run of 20 VS codepoints encoding "test"
        let vs_run = encode_vs_stego(b"test payload here!");
        let content = format!("visible code{}more code", vs_run);

        let findings = detector.detect(&content, "test.js");

        assert!(findings
            .iter()
            .any(|f| f.category == DetectionCategory::SteganoPayload));
    }

    #[test]
    #[cfg(feature = "regex")]
    fn test_pipe_delimiter_detection() {
        let detector = GlasswareDetector::with_default_config();

        // Create pipe delimiter pattern
        let vs_run = encode_vs_stego(b"hidden");
        let content = format!("some|{}data", vs_run);

        let findings = detector.detect(&content, "test.js");

        assert!(findings
            .iter()
            .any(|f| f.category == DetectionCategory::PipeDelimiterStego));
    }

    #[test]
    #[cfg(feature = "regex")]
    fn test_decoder_function_detection() {
        let detector = GlasswareDetector::with_default_config();

        let content = r#"
            const decode = (chars) => {
                return chars.map(c => String.fromCodePoint(
                    c.codePointAt(0) - 0xFE00
                )).join('');
            };
        "#;

        let findings = detector.detect(content, "test.js");

        assert!(findings
            .iter()
            .any(|f| f.category == DetectionCategory::DecoderFunction));
    }

    #[test]
    fn test_clean_content() {
        let detector = GlasswareDetector::with_default_config();
        let content = r#"const normal = 'hello world';"#;
        let findings = detector.detect(content, "test.js");
        assert!(findings.is_empty());
    }
}
