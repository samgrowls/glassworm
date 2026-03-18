# glassware — Developer Handoff

**Last updated:** 2026-03-17  
**Version:** 0.1.0  
**Status:** Production-ready

---

## Quick Start

```bash
# Clone and build
git clone https://github.com/samgrowls/glassware.git
cd glassware
cargo build --release

# Run tests
cargo test --features "full,llm"

# Scan a project
./target/release/glassware /path/to/project

# Scan with LLM analysis (requires API key)
cp .env.example .env
# Edit .env with your API credentials
./target/release/glassware --llm /path/to/project
```

---

## What is glassware?

**glassware** is a Rust-based security scanner that detects invisible Unicode attacks and steganographic payloads in source code. Built in response to the GlassWare threat campaign (active since October 2025), which compromised 72+ VS Code extensions and 150+ GitHub repositories.

**Key differentiator:** glassware doesn't just flag suspicious patterns — it **decodes and displays** hidden payloads, showing you exactly what the attacker embedded.

---

## Architecture Overview

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

### Workspace Structure

```
glassware/
├── Cargo.toml              # Workspace root
├── glassware-core/         # Core library
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                  # Public API re-exports
│       ├── detector.rs             # Detector trait
│       ├── engine.rs               # ScanEngine orchestrator
│       ├── finding.rs              # Finding, DetectionCategory, Severity
│       ├── config.rs               # UnicodeConfig, SensitivityLevel
│       ├── scanner.rs              # UnicodeScanner (L1 regex detectors)
│       ├── semantic.rs             # OXC semantic analysis (L2)
│       ├── taint.rs                # Taint tracking, source/sink/flow
│       ├── decoder.rs              # Steganographic payload decoder
│       ├── classify.rs             # Character classification
│       ├── ranges.rs               # Unicode range definitions
│       ├── script_detector.rs      # Homoglyph script detection
│       ├── confusables/            # Confusable character data
│       ├── detectors/              # L1 regex detector implementations
│       │   ├── mod.rs
│       │   ├── invisible.rs
│       │   ├── homoglyph.rs
│       │   ├── bidi.rs
│       │   ├── glassware.rs
│       │   └── tags.rs
│       ├── encrypted_payload_detector.rs  # GW005 regex
│       ├── header_c2_detector.rs          # GW008 regex
│       ├── gw005_semantic.rs              # GW005 semantic
│       ├── gw006_semantic.rs              # GW006 semantic
│       ├── gw007_semantic.rs              # GW007 semantic
│       ├── gw008_semantic.rs              # GW008 semantic
│       └── llm/                    # L3 LLM layer
│           ├── mod.rs
│           ├── config.rs           # LlmConfig, LlmConfigError
│           └── analyzer.rs         # OpenAiCompatibleAnalyzer
└── glassware-cli/            # CLI binary
    ├── Cargo.toml
    └── src/
        └── main.rs                   # CLI entry point
```

---

## Detection Catalog

| ID | Name | Category | Severity | Description |
|----|------|----------|----------|-------------|
| GW001 | SteganoPayload | `stegano_payload` | Critical | Dense runs of VS codepoints encoding hidden data |
| GW002 | DecoderFunction | `decoder_function` | High | `codePointAt` + VS range constants pattern |
| GW003 | InvisibleCharacter | `invisible_character` | Critical-High | ZWSP, ZWNJ, ZWJ, variation selectors, bidi |
| GW004 | BidirectionalOverride | `bidirectional_override` | Critical | Trojan Source bidi overrides |
| GW005 | EncryptedPayload | `encrypted_payload` | High | High-entropy blob + dynamic execution flow |
| GW006 | HardcodedKeyDecryption | `hardcoded_key_decryption` | High | Crypto API with hardcoded key → exec flow |
| GW007 | Rc4Pattern | `rc4_pattern` | Info | Hand-rolled RC4-like cipher + exec |
| GW008 | HeaderC2 | `header_c2` | Critical | HTTP header extraction + decrypt + exec flow |

---

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `full` | All features enabled | ✅ Yes |
| `minimal` | Only invisible chars + bidi (no regex) | ❌ No |
| `semantic` | OXC-based semantic analysis (JS/TS only) | ✅ Yes (via `full`) |
| `llm` | LLM review layer | ✅ Yes (via `full`) |
| `regex` | Regex-based pattern detection | ✅ Yes (via `full`) |
| `serde` | Serialization support | ✅ Yes (via `full`) |

### Build Combinations

```bash
# Minimal build (smallest binary, fastest)
cargo build --no-default-features --features minimal

# Standard build (regex detectors only)
cargo build --no-default-features --features "regex,serde"

# Full build with semantic analysis
cargo build --features "full"

# Full build with LLM layer
cargo build --features "full,llm"
```

---

## Testing

### Test Counts

| Feature Set | Test Count |
|-------------|------------|
| `--no-default-features` | 106 |
| `--features "full"` | 114 |
| `--features "full,llm"` | 114 |

### Run Tests

```bash
# All tests
cargo test --features "full,llm"

# Specific package
cargo test -p glassware-core
cargo test -p glassware-cli

# Specific test
cargo test gw006_semantic::tests::test_hardcoded_key_to_eval

# LLM tests (require no network, use mocks)
cargo test --features llm llm::
```

---

## Quality Gates

All PRs must pass:

```bash
# Format
cargo fmt --all -- --check

# Lint (zero warnings)
cargo clippy --features "full,llm" -- -D warnings

# Tests
cargo test --features "full,llm"

# Docs
cargo doc --no-deps --features "full,llm"
```

---

## CLI Reference

```bash
glassware [OPTIONS] <PATHS>...

Arguments:
  <PATHS>...  Files or directories to scan

Options:
  -f, --format <FORMAT>        Output format: pretty, json, sarif [default: pretty]
  -s, --severity <SEVERITY>    Minimum severity: low, medium, high, critical [default: low]
  -q, --quiet                  Suppress output, only set exit code
      --no-color               Disable colored output
      --extensions <EXTS>      File extensions (comma-separated)
      --exclude <DIRS>         Directories to exclude (comma-separated)
      --llm                    Run LLM analysis on flagged files
  -h, --help                   Print help
  -V, --version                Print version
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above severity threshold |
| 1 | Findings detected |
| 2 | Error (file not found, permission denied) |

---

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

---

## Adding a New Detector

### Step 1: Create Detector Module

```rust
// src/gwXXX_semantic.rs
use crate::detector::SemanticDetector;
use crate::finding::{DetectionCategory, Finding, Severity};
use std::path::Path;

pub struct GwXXXSemanticDetector;

impl SemanticDetector for GwXXXSemanticDetector {
    fn id(&self) -> &str { "GWXXX" }

    fn detect_semantic(
        &self,
        source: &str,
        path: &Path,
        flows: &[TaintFlow],
        sources: &[TaintSource],
        sinks: &[TaintSink],
    ) -> Vec<Finding> {
        // Implementation
    }
}
```

### Step 2: Add DetectionCategory Variant

```rust
// src/finding.rs
pub enum DetectionCategory {
    // ... existing variants ...
    YourNewCategory,
}
```

### Step 3: Register in Engine

```rust
// src/engine.rs
pub fn default_detectors() -> Self {
    let mut engine = Self::new();
    // ... existing registrations ...
    #[cfg(feature = "semantic")]
    {
        engine.register_semantic(Box::new(crate::gwXXX_semantic::GwXXXSemanticDetector::new()));
    }
    engine
}
```

### Step 4: Add Tests

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_true_positive() { ... }

    #[test]
    fn test_false_positive() { ... }
}
```

---

## Known Limitations

1. **Semantic analysis is JS/TS only** — OXC parser only supports JavaScript/TypeScript
2. **LLM layer requires network access** — Falls back gracefully if unavailable
3. **RC4 detection is heuristic** — May have false positives on legitimate crypto code
4. **No multi-hop taint tracking** — Only one-hop transitive flows are tracked

---

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

---

## Troubleshooting

### Build Errors

```bash
# Clean and rebuild
cargo clean && cargo build

# Update dependencies
cargo update

# Check Rust version (requires 1.70+)
rustc --version
```

### Test Failures

```bash
# Run with verbose output
cargo test --features "full,llm" -- --nocapture

# Run specific test module
cargo test gw006_semantic --features "full,llm" -- --nocapture
```

### LLM Errors

```bash
# Verify environment variables
echo $GLASSWARE_LLM_BASE_URL
echo $GLASSWARE_LLM_API_KEY

# Test API connectivity
curl -H "Authorization: Bearer $GLASSWARE_LLM_API_KEY" \
     "$GLASSWARE_LLM_BASE_URL/models"
```

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all quality gates pass
5. Submit a pull request

---

## Security Considerations

- **No network calls in L1/L2** — Detection is fully offline
- **LLM layer is opt-in** — Requires explicit `--llm` flag
- **API keys never logged** — Credentials handled securely
- **Decoded payloads sanitized** — Hidden code displayed safely

---

## Contact

- **GitHub:** https://github.com/samgrowls/glassware
- **Issues:** https://github.com/samgrowls/glassware/issues

---

## License

MIT License — see LICENSE file for details.
