# glassware - Project Context

## Project Overview

**glassware** is a Rust-based security tool that detects steganographic payloads, invisible Unicode characters, and bidirectional text attacks in source code. It was created in response to the GlassWare threat campaign (active since October 2025) which compromised 72+ VS Code extensions and 150+ GitHub repositories using invisible Unicode steganography.

### Architecture

This is a **Cargo workspace** with two members:

| Package | Description |
|---------|-------------|
| `glassware-core` | Core detection library with three-layer detection (regex, semantic, LLM) |
| `glassware-cli` | CLI binary (`glassware`) that uses the core library |

### Three-Layer Detection System

```
┌─────────────────────────────────────────────────────────────┐
│                     ScanEngine                               │
├─────────────────────────────────────────────────────────────┤
│  L1: Regex Detectors (all files)                            │
│      - InvisibleCharDetector                                │
│      - HomoglyphDetector                                    │
│      - BidiDetector                                         │
│      - GlassWareDetector                                    │
│      - UnicodeTagDetector                                   │
│      - EncryptedPayloadDetector (GW005 regex)               │
│      - HeaderC2Detector (GW008 regex)                       │
├─────────────────────────────────────────────────────────────┤
│  L2: Semantic Detectors (JS/TS only, requires OXC)          │
│      - Gw005SemanticDetector (stego → exec flow)            │
│      - Gw006SemanticDetector (hardcoded key → exec)         │
│      - Gw007SemanticDetector (RC4 cipher → exec)            │
│      - Gw008SemanticDetector (header C2 → decrypt → exec)   │
├─────────────────────────────────────────────────────────────┤
│  L3: LLM Review (flagged files only, optional)              │
│      - OpenAiCompatibleAnalyzer                             │
│      - Intent-level reasoning                               │
│      - False positive reduction                             │
└─────────────────────────────────────────────────────────────┘
```

### Key Detection Capabilities

| ID | Detection | Severity | Description |
|----|-----------|----------|-------------|
| GW001 | SteganoPayload | Critical | Dense runs of Unicode Variation Selectors encoding hidden data |
| GW002 | DecoderFunction | High | `codePointAt` + 0xFE00/0xE0100 patterns matching GlassWare decoder logic |
| GW003 | InvisibleCharacter | Critical-High | ZWSP, ZWNJ, ZWJ, word joiners, variation selectors |
| GW004 | BidirectionalOverride | Critical | Trojan Source bidirectional text overrides |
| GW005 | EncryptedPayload | High | High-entropy blob + dynamic execution flow |
| GW006 | HardcodedKeyDecryption | High | Crypto API with hardcoded key → exec flow |
| GW007 | Rc4Pattern | Info | Hand-rolled RC4-like cipher + exec |
| GW008 | HeaderC2 | Critical | HTTP header extraction + decrypt + exec flow |
| - | PipeDelimiterStego | Critical | VS codepoints after pipe delimiter (npm variant) |
| - | Homoglyph | Medium-High | Mixed-script identifiers using Cyrillic/Greek lookalikes |
| - | UnicodeTag | High | Unicode tag characters (U+E0001–U+E007F) |

### Core Modules (glassware-core)

```
glassware-core/src/
├── lib.rs                      # Main library entry point, re-exports public API
├── detector.rs                 # Detector trait definition
├── engine.rs                   # ScanEngine orchestrator with LLM support
├── finding.rs                  # Finding, DetectionCategory, Severity types
├── config.rs                   # UnicodeConfig, DetectorConfig, SensitivityLevel
├── scanner.rs                  # UnicodeScanner (L1 regex detectors)
├── semantic.rs                 # OXC semantic analysis (L2)
├── taint.rs                    # Taint tracking: source/sink/flow
├── decoder.rs                  # Steganographic payload decoder (VS → bytes)
├── classify.rs                 # Character classification utilities
├── ranges.rs                   # Unicode range definitions
├── script_detector.rs          # Script detection for homoglyph analysis
├── confusables/                # Confusable character data
├── detectors/                  # L1 regex detector implementations
│   ├── mod.rs
│   ├── invisible.rs
│   ├── homoglyph.rs
│   ├── bidi.rs
│   ├── glassware.rs
│   └── tags.rs
├── encrypted_payload_detector.rs   # GW005 regex detector
├── header_c2_detector.rs           # GW008 regex detector
├── gw005_semantic.rs               # GW005 semantic detector
├── gw006_semantic.rs               # GW006 semantic detector
├── gw007_semantic.rs               # GW007 semantic detector
├── gw008_semantic.rs               # GW008 semantic detector
└── llm/                            # L3 LLM layer
    ├── mod.rs
    ├── config.rs                   # LlmConfig, LlmConfigError
    └── analyzer.rs                 # OpenAiCompatibleAnalyzer
```

## Building and Running

### Prerequisites

- Rust 1.70 or later
- Cargo

### Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `full` | All features enabled | ✅ Yes |
| `minimal` | Only invisible chars + bidi (no regex) | ❌ No |
| `semantic` | OXC-based semantic analysis (JS/TS only) | ✅ Yes (via `full`) |
| `llm` | LLM review layer | ✅ Yes (via `full`) |
| `regex` | Regex-based pattern detection | ✅ Yes (via `full`) |
| `serde` | Serialization support | ✅ Yes (via `full`) |

### Build Commands

```bash
# Build entire workspace (debug)
cargo build

# Build with all features
cargo build --features "full,llm"

# Build release (optimized binary)
cargo build --release

# Minimal build (smallest binary)
cargo build --no-default-features --features minimal

# Run CLI directly
cargo run -- project/

# Run tests
cargo test --features "full,llm"

# Run tests for specific package
cargo test -p glassware-core
cargo test -p glassware-cli

# Install CLI globally
cargo install --path glassware-cli
```

### CLI Usage

```bash
# Scan a directory
glassware .

# Scan specific files
glassware src/index.js package.json

# JSON output
glassware --format json .

# SARIF output (GitHub Advanced Security)
glassware --format sarif . > results.sarif

# Only critical/high findings
glassware --severity high .

# Silent mode — exit code only
glassware --quiet .

# LLM analysis (requires API key)
glassware --llm .
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--format`, `-f` | Output format: `pretty`, `json`, `sarif` | `pretty` |
| `--severity`, `-s` | Minimum severity: `info`, `low`, `medium`, `high`, `critical` | `low` |
| `--quiet`, `-q` | Suppress output, only set exit code | `false` |
| `--no-color` | Disable colored output | `false` |
| `--extensions` | File extensions to include (comma-separated) | `js,mjs,cjs,ts,tsx,jsx,py,rs,go,...` |
| `--exclude` | Directories to exclude (comma-separated) | `.git,node_modules,target,...` |
| `--llm` | Run LLM analysis on flagged files | `false` |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above severity threshold |
| 1 | Findings detected |
| 2 | Error (file not found, permission denied) |

## LLM Layer Configuration

### Environment Variables

```bash
# Required for --llm flag
export GLASSWARE_LLM_BASE_URL="https://api.cerebras.ai/v1"
export GLASSWARE_LLM_API_KEY="your-api-key"

# Optional (defaults to llama-3.3-70b)
export GLASSWARE_LLM_MODEL="llama-3.3-70b"
```

### Supported Providers

| Provider | Base URL | Recommended Model |
|----------|----------|-------------------|
| Cerebras | `https://api.cerebras.ai/v1` | `llama-3.3-70b` |
| Groq | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o` |
| NVIDIA NIM | `https://integrate.api.nvidia.com/v1` | `meta/llama-3.3-70b-instruct` |
| Ollama (local) | `http://localhost:11434/v1` | `llama3.3` |

### .env File

```bash
cp .env.example .env
# Edit .env with your credentials
```

## Development Conventions

### Code Style

- **Edition**: Rust 2021
- **Documentation**: All public types, functions, and enum variants have doc comments
- **Public API**: Re-exported from `lib.rs` for convenient access
- **Features**: `full` (default), `minimal`, `serde`, `llm` for conditional compilation
- **Linting**: `cargo clippy -- -D warnings` must pass with no warnings

### Testing Practices

- Unit tests in each module using `#[cfg(test)]`
- Tests cover: variation selectors, homoglyphs, bidi overrides, clean content
- Decoder tests include round-trip encoding/decoding verification
- Entropy analysis tests for payload classification
- LLM tests use mocks (no network calls)
- **All 114 tests must pass before merging** (with `full,llm` features)

### Key Design Decisions

1. **Zero-dependency core (L1)**: The regex detection engine minimizes external dependencies
2. **O(n) time complexity**: Single-pass character scanning for L1 detectors
3. **Shannon entropy analysis**: Classifies decoded payloads (plaintext vs encrypted)
4. **Payload decoding**: Actually decodes and displays hidden payloads, not just flags them
5. **Context-aware detection**: Homoglyph detector skips pure non-Latin identifiers (i18n-friendly)
6. **Semantic flow tracking (L2)**: OXC-based taint analysis for JS/TS encrypted loaders
7. **LLM review (L3)**: Optional AI analysis for intent-level reasoning and FP reduction
8. **Graceful degradation**: LLM layer fails silently if unavailable

### Adding New Detectors

#### L1 Regex Detector

1. Create new detector module in `glassware-core/src/detectors/`
2. Implement detection logic returning `Vec<Finding>`
3. Add to `DetectorConfig` in `config.rs`
4. Register in `UnicodeScanner` in `scanner.rs`
5. Add to `DetectionCategory` enum in `finding.rs`

#### L2 Semantic Detector

1. Create `gwXXX_semantic.rs` in `glassware-core/src/`
2. Implement `SemanticDetector` trait
3. Register in `ScanEngine::default_detectors()`
4. Add to `DetectionCategory` enum in `finding.rs`
5. Write tests for true positives and false positives

### Configuration Presets

```rust
// Default configuration
UnicodeConfig::default()

// More permissive (i18n projects)
UnicodeConfig::for_i18n_project()

// Stricter (high-security projects)
UnicodeConfig::for_high_security()
```

### Quality Checks

```bash
# Format code
cargo fmt --all

# Run clippy (must pass with no warnings)
cargo clippy --features "full,llm" -- -D warnings

# Run all tests
cargo test --features "full,llm"

# Build documentation
cargo doc --no-deps --features "full,llm"

# Test all feature combinations
cargo test --no-default-features
cargo test --features "full"
cargo test --features "full,llm"
```

## Performance Benchmarks

| Metric | Value |
|--------|-------|
| Binary size (minimal) | ~1.2 MB |
| Binary size (full) | ~8 MB |
| Scan speed | ~50k LOC/sec |
| Memory usage | ~50 MB peak |
| L1 detection latency | O(n) single pass |
| L2 detection latency | O(n²) worst case |
| L3 detection latency | ~2-5 sec per file (API dependent) |

## Related Projects

- **Coax**: Full code trust scanner (secrets detection, Unicode attacks, entropy analysis). glassware's detection engine originated from Coax.
- **anti-trojan-source**: JavaScript-based Trojan Source detector (less feature-complete than glassware)
