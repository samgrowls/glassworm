# glassware

**One binary. Zero dependencies. Finds invisible attacks hiding in your code.**

glassware detects steganographic payloads, invisible Unicode characters, and bidirectional text attacks in source code. Built in Rust. Ships as a single binary.

## Why

In March 2026, the GlassWare campaign compromised 72+ VS Code extensions and 150+ GitHub repositories using invisible Unicode characters to hide malicious payloads in plain sight. The code looks normal in your editor. The payload is invisible. glassware makes it visible.

```
$ glassware project/

⚠ CRITICAL project/preinstall.js:47
  Steganographic payload detected
  Hidden: 8,412 invisible codepoints → 8,412 bytes decoded
  Entropy: 7.98 bits/byte — encrypted or compressed payload

⚠ CRITICAL project/index.js:23
  Steganographic payload detected
  Hidden: 1,247 invisible codepoints → 1,247 bytes decoded
  Entropy: 4.72 bits/byte — plaintext code

┌─ Decoded payload ──────────────────────────────────┐
│ const https = require('https');                    │
│ const os = require('os');                          │
│ const data = JSON.stringify({                      │
│   hostname: os.hostname(),                         │
│   platform: os.platform(),                         │
│   ...                                              │
│   (1,247 bytes total — showing first 512)          │
└─────────────────────────────────────────────────────┘

⚠ HIGH project/utils.js:12
  GlassWare decoder function detected
  Pattern: codePointAt with variation selector range constants (0xFE00)

3 findings in 847 files (0.12s)
```

## Install

**From source (recommended):**

```bash
cargo install --path glassware-cli
```

**From binary release:**

```bash
# macOS / Linux
curl -sSL https://github.com/samgrowls/glassware/releases/latest/download/glassware-$(uname -s)-$(uname -m) -o glassware
chmod +x glassware
```

Verify checksums against the SHA256 values listed in each release.

## Usage

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

## What It Detects

| Detection | Severity | Description |
|-----------|----------|-------------|
| VS Stego Payload | Critical | Dense runs of Unicode Variation Selectors encoding hidden data |
| Decoder Function | High | `codePointAt` + 0xFE00/0xE0100 patterns matching GlassWare decoder logic |
| Bidi Override | Critical | Bidirectional text overrides that reorder displayed code (Trojan Source) |
| Zero-Width Characters | Medium–High | ZWSP, ZWNJ, ZWJ, word joiners in code contexts |
| Homoglyphs | Medium–High | Mixed-script identifiers using Cyrillic/Greek lookalikes |
| Tag Characters | High | Unicode tag characters (U+E0001–U+E007F) in source files |
| Encrypted Payload (GW005) | High | High-entropy blob + dynamic execution flow |
| Hardcoded Key (GW006) | High | Crypto API with hardcoded key → exec flow |
| RC4 Pattern (GW007) | Info | Hand-rolled RC4-like cipher + exec |
| Header C2 (GW008) | Critical | HTTP header extraction + decrypt + exec flow |

## Decoded Payload Display

When glassware finds a steganographic payload, it doesn't just flag it — it decodes and displays what's hidden. For unencrypted payloads, you see the actual malicious code. For encrypted payloads, you see byte count, entropy score, and a hex preview.

## LLM Analysis (Optional)

The `--llm` flag enables AI-powered review of flagged files. glassware sends suspicious code to your chosen LLM provider for intent-level analysis and false positive reduction.

```bash
# Configure via environment
export GLASSWARE_LLM_BASE_URL="https://api.cerebras.ai/v1"
export GLASSWARE_LLM_API_KEY="your-key"
glassware --llm .

# Or use .env file
cp .env.example .env
# Edit .env with your credentials
glassware --llm .
```

Supported providers: Cerebras, Groq, OpenAI, NVIDIA NIM, Ollama (local).

## CI Integration

### GitHub Actions

```yaml
name: glassware
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install glassware
        run: cargo install --path glassware-cli
      - name: Scan
        run: glassware .
```

Exit code 1 on findings, 0 when clean.

### SARIF Upload (GitHub Advanced Security)

```yaml
- name: Scan (SARIF)
  run: glassware --format sarif . > results.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Findings appear directly in the Security tab and as PR annotations.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above severity threshold |
| 1 | Findings detected |
| 2 | Error (file not found, permission denied) |

## How It Works

glassware scans source files character by character, classifying each Unicode codepoint. When it finds suspicious characters — invisible formatters, bidi overrides, variation selectors, tag characters — it evaluates density, context (comment, string, identifier), and file type to determine severity.

For steganographic payloads, glassware reverses the encoding: Unicode Variation Selectors (U+FE00–U+FE0F, U+E0100–U+E01EF) map to byte values 0x00–0xFF via a simple substitution cipher. The resulting bytes are analyzed for entropy. High entropy (>7.0 bits/byte) indicates encrypted content. Low entropy with valid UTF-8 indicates readable code — which glassware displays directly.

**Three-layer detection:**
1. **L1: Regex detectors** — Fast pattern matching on all file types
2. **L2: Semantic analysis** — OXC-based flow tracking for JS/TS (detects encrypted loaders, C2 patterns)
3. **L3: LLM review** — Optional AI analysis for intent-level reasoning

No network calls in L1/L2. No config files. No dependencies beyond the binary itself.

## Scanning VS Code Extensions

VS Code extensions (.vsix files) are zip archives:

```bash
unzip suspicious.vsix -d temp/
glassware temp/
rm -rf temp/
```

## The GlassWare Campaign

glassware is named after the GlassWare threat campaign, active since October 2025. The campaign uses invisible Unicode steganography to hide malicious payloads in JavaScript/TypeScript files across npm packages, GitHub repositories, and VS Code extensions.

## Comparison

| Feature | glassware | anti-trojan-source |
|---------|-----------|-------------------|
| Language | Rust (single binary) | JavaScript (requires Node.js) |
| Stego decoding | ✅ Decodes + displays payload | ❌ |
| Entropy analysis | ✅ | ❌ |
| SARIF output | ✅ | ❌ |
| Bidi detection | ✅ | ✅ |
| Zero-width detection | ✅ | ✅ |
| Homoglyphs | ✅ | ❌ |
| Semantic analysis | ✅ OXC-based flow tracking | ❌ |
| LLM review | ✅ Optional | ❌ |
| Install | `cargo install` / single binary | `npm install` |

## Related

- **Coax** — Full code trust scanner. Secrets detection, Unicode attacks, entropy analysis, verification. glassware's detection engine originated from Coax.

## License

MIT License — see LICENSE file for details.
