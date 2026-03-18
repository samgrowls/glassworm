//! GlassWare - Unicode Attack Scanner CLI
//!
//! Detects invisible Unicode attacks in source code including:
//! - Steganographic payloads using Variation Selectors
//! - Bidirectional text overrides (Trojan Source)
//! - Homoglyph attacks
//! - GlassWare decoder patterns

use clap::{Parser, ValueEnum};
use colored::Colorize;
use glassware_core::{
    DecodedPayload, DetectionCategory, Finding, PayloadClass, ScanEngine, Severity,
};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

/// GlassWare - Detect invisible Unicode attacks in source code
#[derive(Parser, Debug)]
#[command(name = "glassware")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Files or directories to scan
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "pretty")]
    format: OutputFormat,

    /// Minimum severity to report
    #[arg(short, long, value_enum, default_value = "low")]
    severity: SeverityLevel,

    /// Suppress output, only set exit code
    #[arg(short, long, default_value = "false")]
    quiet: bool,

    /// Disable colored output
    #[arg(long, default_value = "false")]
    no_color: bool,

    /// File extensions to include (comma-separated)
    #[arg(
        long,
        default_value = "js,mjs,cjs,ts,tsx,jsx,py,rs,go,java,rb,php,sh,bash,zsh,yml,yaml,toml,json,xml,md,txt"
    )]
    extensions: String,

    /// Directories to exclude (comma-separated)
    #[arg(
        long,
        default_value = ".git,node_modules,target,__pycache__,.venv,vendor"
    )]
    exclude: String,

    /// Run LLM analysis on flagged files (requires GLASSWARE_LLM_BASE_URL and
    /// GLASSWARE_LLM_API_KEY environment variables, or a .env file)
    #[cfg(feature = "llm")]
    #[arg(long, default_value = "false")]
    llm: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Pretty,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, PartialOrd)]
enum SeverityLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityLevel {
    fn matches(&self, severity: &Severity) -> bool {
        let finding_level = match severity {
            Severity::Low | Severity::Info => SeverityLevel::Low,
            Severity::Medium => SeverityLevel::Medium,
            Severity::High => SeverityLevel::High,
            Severity::Critical => SeverityLevel::Critical,
        };
        finding_level >= *self
    }
}

#[derive(Debug, Serialize)]
struct JsonOutput {
    version: String,
    findings: Vec<JsonFinding>,
    summary: JsonSummary,
}

#[derive(Debug, Serialize)]
struct JsonFinding {
    file: String,
    line: usize,
    column: usize,
    severity: String,
    category: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded: Option<JsonDecodedPayload>,
}

#[derive(Debug, Serialize)]
struct JsonDecodedPayload {
    byte_count: usize,
    entropy: f64,
    payload_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview_text: Option<String>,
}

#[derive(Debug, Serialize)]
struct JsonSummary {
    files_scanned: usize,
    findings_count: usize,
    duration_ms: u64,
}

fn main() {
    let args = Args::parse();

    // Disable colors if requested
    if args.no_color {
        colored::control::set_override(false);
    }

    // Collect files to scan
    let files = collect_files(&args);

    if files.is_empty() {
        eprintln!("No files to scan");
        std::process::exit(2);
    }

    // Create scan engine with default detectors
    #[cfg(feature = "llm")]
    let engine = ScanEngine::default_detectors().with_llm(args.llm);
    #[cfg(not(feature = "llm"))]
    let engine = ScanEngine::default_detectors();

    let start = Instant::now();
    let mut all_findings = Vec::new();
    #[cfg(feature = "llm")]
    let mut all_llm_verdicts = Vec::new();

    // Scan each file
    for file in &files {
        if let Ok(content) = fs::read_to_string(file) {
            #[cfg(feature = "llm")]
            {
                let result = engine.scan_with_llm(file, &content);
                all_findings.extend(result.findings);
                all_llm_verdicts.extend(result.llm_verdicts);
            }
            #[cfg(not(feature = "llm"))]
            {
                let findings = engine.scan(file, &content);
                all_findings.extend(findings);
            }
        }
    }

    let duration = start.elapsed();

    // Filter by severity
    let filtered_findings: Vec<_> = all_findings
        .into_iter()
        .filter(|f| args.severity.matches(&f.severity))
        .collect();

    // Output results
    let has_findings = !filtered_findings.is_empty();

    if !args.quiet {
        match args.format {
            OutputFormat::Pretty => {
                #[cfg(feature = "llm")]
                {
                    let filtered_llm_verdicts: Vec<_> = all_llm_verdicts
                        .iter()
                        .filter(|v| files.iter().any(|f| f == &v.file_path))
                        .cloned()
                        .collect();
                    output_pretty_with_llm(
                        &filtered_findings,
                        &files,
                        duration,
                        &filtered_llm_verdicts,
                    );
                }
                #[cfg(not(feature = "llm"))]
                {
                    output_pretty(&filtered_findings, &files, duration);
                }
            }
            OutputFormat::Json => output_json(&filtered_findings, &files, duration),
            OutputFormat::Sarif => output_sarif(&filtered_findings, &files, duration),
        }
    }

    // Exit code
    if has_findings {
        std::process::exit(1);
    } else {
        std::process::exit(0);
    }
}

/// Collect files to scan from the provided paths
fn collect_files(args: &Args) -> Vec<PathBuf> {
    let extensions: Vec<&str> = args.extensions.split(',').collect();
    let exclude_dirs: Vec<&str> = args.exclude.split(',').collect();
    let mut files = Vec::new();

    for path in &args.paths {
        if path.is_file() {
            if should_scan_file(path, &extensions) {
                files.push(path.clone());
            }
        } else if path.is_dir() {
            for entry in WalkDir::new(path)
                .into_iter()
                .filter_entry(|e| !should_exclude_dir(e.path(), &exclude_dirs))
                .filter_map(|e| e.ok())
            {
                let entry_path = entry.path();
                if entry_path.is_file() && should_scan_file(entry_path, &extensions) {
                    files.push(entry_path.to_path_buf());
                }
            }
        }
    }

    files
}

/// Check if a file should be scanned based on extension
fn should_scan_file(path: &Path, extensions: &[&str]) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        extensions.contains(&ext)
    } else {
        false
    }
}

/// Check if a directory should be excluded
fn should_exclude_dir(path: &Path, exclude_dirs: &[&str]) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        exclude_dirs.contains(&name)
    } else {
        false
    }
}

/// Output results in pretty format
#[cfg(feature = "llm")]
fn output_pretty_with_llm(
    findings: &[Finding],
    files: &[PathBuf],
    duration: std::time::Duration,
    llm_verdicts: &[glassware_core::llm::LlmFileResult],
) {
    if findings.is_empty() {
        println!("{}", "✓ No Unicode attacks detected".green().bold());
        println!(
            "Scanned {} files in {:.2}s",
            files.len(),
            duration.as_secs_f64()
        );
        return;
    }

    // Group findings by severity
    let critical: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .collect();
    let high: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .collect();
    let medium: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .collect();
    let low: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Low || f.severity == Severity::Info)
        .collect();

    for finding in &critical {
        print_finding(finding, "CRITICAL", "red");
    }

    for finding in &high {
        print_finding(finding, "HIGH", "yellow");
    }

    for finding in &medium {
        print_finding(finding, "MEDIUM", "blue");
    }

    for finding in &low {
        print_finding(finding, "LOW", "cyan");
    }

    // Display LLM verdicts
    if !llm_verdicts.is_empty() {
        println!();
        println!("{}", "━".repeat(60).dimmed());
        println!("{}", "LLM Analysis".bold().magenta());
        println!("{}", "━".repeat(60).dimmed());

        for verdict_result in llm_verdicts {
            println!();
            println!(
                "{}",
                format!("File: {}", verdict_result.file_path.display()).dimmed()
            );
            let verdict = &verdict_result.verdict;
            let verdict_str = if verdict.is_malicious {
                "MALICIOUS".red().bold()
            } else {
                "BENIGN".green().bold()
            };
            println!(
                "  Verdict:    {} (confidence: {:.2})",
                verdict_str, verdict.confidence
            );
            if let Some(ref sev) = verdict.reclassified_severity {
                println!("  Severity:   {} (reclassified)", sev);
            }
            println!("  Reasoning:  {}", wrap_text(&verdict.reasoning, 72));
        }
    }

    // Summary
    println!("{}", "━".repeat(60).dimmed());
    println!(
        "{} in {} files ({} critical, {} high, {} medium, {} low)",
        format!("{} findings", findings.len()).bold(),
        files.len(),
        critical.len().to_string().red(),
        high.len().to_string().yellow(),
        medium.len().to_string().blue(),
        low.len().to_string().cyan()
    );
    println!(
        "Scanned {} files in {:.2}s",
        files.len(),
        duration.as_secs_f64()
    );
}

/// Output results in pretty format (without LLM)
#[cfg(not(feature = "llm"))]
fn output_pretty(findings: &[Finding], files: &[PathBuf], duration: std::time::Duration) {
    if findings.is_empty() {
        println!("{}", "✓ No Unicode attacks detected".green().bold());
        println!(
            "Scanned {} files in {:.2}s",
            files.len(),
            duration.as_secs_f64()
        );
        return;
    }

    // Group findings by severity
    let critical: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .collect();
    let high: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .collect();
    let medium: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .collect();
    let low: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Low || f.severity == Severity::Info)
        .collect();

    for finding in &critical {
        print_finding(finding, "CRITICAL", "red");
    }

    for finding in &high {
        print_finding(finding, "HIGH", "yellow");
    }

    for finding in &medium {
        print_finding(finding, "MEDIUM", "blue");
    }

    for finding in &low {
        print_finding(finding, "LOW", "cyan");
    }

    // Summary
    println!("{}", "━".repeat(60).dimmed());
    println!(
        "{} in {} files ({} critical, {} high, {} medium, {} low)",
        format!("{} findings", findings.len()).bold(),
        files.len(),
        critical.len().to_string().red(),
        high.len().to_string().yellow(),
        medium.len().to_string().blue(),
        low.len().to_string().cyan()
    );
    println!(
        "Scanned {} files in {:.2}s",
        files.len(),
        duration.as_secs_f64()
    );
}

/// Wrap text to a maximum width
#[cfg(feature = "llm")]
fn wrap_text(text: &str, max_width: usize) -> String {
    let mut result = String::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.len() + word.len() + 1 > max_width {
            if !result.is_empty() {
                result.push('\n');
                result.push_str(&" ".repeat(14));
            }
            result.push_str(&current_line);
            current_line.clear();
        }
        if !current_line.is_empty() {
            current_line.push(' ');
        }
        current_line.push_str(word);
    }

    if !current_line.is_empty() {
        if !result.is_empty() {
            result.push('\n');
            result.push_str(&" ".repeat(14));
        }
        result.push_str(&current_line);
    }

    result
}

/// Print a single finding in pretty format
fn print_finding(finding: &Finding, level: &str, color: &str) {
    let level_colored = match color {
        "red" => format!("⚠ {}", level).red().bold(),
        "yellow" => format!("⚠ {}", level).yellow().bold(),
        "blue" => format!("⚠ {}", level).blue().bold(),
        "cyan" => format!("⚠ {}", level).cyan().bold(),
        _ => level.to_string().into(),
    };

    println!();
    println!("{}", level_colored);
    println!("  {}", format!("File: {}", finding.file).dimmed());
    println!("  Line: {}", finding.line);
    println!(
        "  Type: {}",
        finding.category.as_str().replace('_', " ").bold()
    );
    println!("  {}", finding.description);

    // Print decoded payload if available
    if let Some(payload) = &finding.decoded_payload {
        print_decoded_payload(payload);
    }

    println!("  {}", finding.remediation.dimmed());
    println!("{}", "---".dimmed());
}

/// Print decoded payload information
fn print_decoded_payload(payload: &DecodedPayload) {
    println!(
        "  {}",
        format!(
            "Hidden: {} invisible codepoints → {} bytes decoded",
            payload.codepoint_count,
            payload.bytes.len()
        )
        .bold()
    );
    println!("  Entropy: {:.2} bits/byte", payload.entropy);
    println!("  Classification: {}", payload.payload_class.description());

    match &payload.payload_class {
        PayloadClass::PlaintextCode => {
            if let Some(text) = payload.text_preview(512) {
                println!();
                println!(
                    "  {}",
                    "┌─ Decoded payload ─────────────────────────────────┐".dimmed()
                );
                for line in text.lines().take(15) {
                    println!("  {} {}", "│".dimmed(), line);
                }
                if text.lines().count() > 15 {
                    println!(
                        "  {} {}",
                        "│".dimmed(),
                        format!("(... {} bytes total)", payload.bytes.len()).dimmed()
                    );
                }
                println!(
                    "  {}",
                    "└────────────────────────────────────────────────────┘".dimmed()
                );
            }
        }
        PayloadClass::EncryptedOrCompressed | PayloadClass::SuspiciousData => {
            println!(
                "  {} {}",
                "Payload preview (first 64 bytes, hex):".dimmed(),
                payload.hex_preview(32)
            );
        }
        PayloadClass::TooSmall => {}
    }
}

/// Output results in JSON format
fn output_json(findings: &[Finding], files: &[PathBuf], duration: std::time::Duration) {
    let json_findings: Vec<JsonFinding> = findings
        .iter()
        .map(|f| JsonFinding {
            file: f.file.clone(),
            line: f.line,
            column: f.column,
            severity: f.severity.as_str().to_string(),
            category: f.category.as_str().to_string(),
            message: f.description.clone(),
            decoded: f.decoded_payload.as_ref().map(|p| JsonDecodedPayload {
                byte_count: p.bytes.len(),
                entropy: p.entropy,
                payload_class: p.payload_class.as_str().to_string(),
                preview_hex: Some(p.hex_preview(32)),
                preview_text: p.text_preview(128),
            }),
        })
        .collect();

    let output = JsonOutput {
        version: env!("CARGO_PKG_VERSION").to_string(),
        findings: json_findings,
        summary: JsonSummary {
            files_scanned: files.len(),
            findings_count: findings.len(),
            duration_ms: duration.as_millis() as u64,
        },
    };

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

/// Output results in SARIF format
fn output_sarif(findings: &[Finding], _files: &[PathBuf], _duration: std::time::Duration) {
    let sarif = SarifOutput {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "glassware".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/PropertySightlines/glassware".to_string(),
                    rules: vec![
                        SarifRule {
                            id: "GW001".to_string(),
                            name: "SteganoPayload".to_string(),
                            short_description: SarifMessage {
                                text: "Steganographic payload using Unicode Variation Selectors".to_string(),
                            },
                            default_configuration: SarifConfig { level: "error".to_string() },
                        },
                        SarifRule {
                            id: "GW002".to_string(),
                            name: "DecoderFunction".to_string(),
                            short_description: SarifMessage {
                                text: "GlassWare-style decoder function pattern".to_string(),
                            },
                            default_configuration: SarifConfig { level: "warning".to_string() },
                        },
                        SarifRule {
                            id: "GW003".to_string(),
                            name: "InvisibleCharacters".to_string(),
                            short_description: SarifMessage {
                                text: "Invisible Unicode characters in source code".to_string(),
                            },
                            default_configuration: SarifConfig { level: "warning".to_string() },
                        },
                        SarifRule {
                            id: "GW004".to_string(),
                            name: "BidiOverride".to_string(),
                            short_description: SarifMessage {
                                text: "Bidirectional text override (Trojan Source)".to_string(),
                            },
                            default_configuration: SarifConfig { level: "error".to_string() },
                        },
                    ],
                },
            },
            results: findings.iter().map(|f| SarifResult {
                rule_id: match f.category {
                    DetectionCategory::SteganoPayload => "GW001",
                    DetectionCategory::DecoderFunction => "GW002",
                    DetectionCategory::InvisibleCharacter => "GW003",
                    DetectionCategory::BidirectionalOverride => "GW004",
                    DetectionCategory::EncryptedPayload => "GW005",
                    DetectionCategory::HardcodedKeyDecryption => "GW006",
                    DetectionCategory::Rc4Pattern => "GW007",
                    DetectionCategory::HeaderC2 => "GW008",
                    _ => "GW003",
                }.to_string(),
                level: severity_to_sarif_level(&f.severity),
                message: SarifMessage {
                    text: f.description.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: f.file.clone(),
                        },
                        region: Some(SarifRegion {
                            start_line: f.line as u32,
                            start_column: Some(f.column as u32),
                            end_line: None,
                            end_column: None,
                            snippet: f.context.as_ref().map(|c| SarifSnippet { text: c.clone() }),
                        }),
                    },
                }],
            }).collect(),
        }],
    };

    println!("{}", serde_json::to_string_pretty(&sarif).unwrap());
}

fn severity_to_sarif_level(severity: &Severity) -> String {
    match severity {
        Severity::Critical | Severity::High => "error".to_string(),
        Severity::Medium => "warning".to_string(),
        Severity::Low | Severity::Info => "note".to_string(),
    }
}

#[derive(Debug, Serialize)]
struct SarifOutput {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifConfig,
}

#[derive(Debug, Serialize)]
struct SarifConfig {
    level: String,
}

#[derive(Debug, Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Debug, Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    #[serde(rename = "region", skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Debug, Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: u32,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    start_column: Option<u32>,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    end_line: Option<u32>,
    #[serde(rename = "endColumn", skip_serializing_if = "Option::is_none")]
    end_column: Option<u32>,
    #[serde(rename = "snippet", skip_serializing_if = "Option::is_none")]
    snippet: Option<SarifSnippet>,
}

#[derive(Debug, Serialize)]
struct SarifSnippet {
    text: String,
}
