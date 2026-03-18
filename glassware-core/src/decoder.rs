//! Steganographic Payload Decoder
//!
//! Decodes hidden payloads from Unicode Variation Selector (VS) codepoints
//! used in GlassWare-style attacks.
//!
//! ## Encoding Scheme
//!
//! The GlassWare campaign uses a substitution cipher mapping 256 invisible
//! Unicode codepoints to all 256 byte values (0x00-0xFF):
//!
//! - U+FE00 through U+FE0F → byte values 0-15 (16 Variation Selector codepoints)
//! - U+E0100 through U+E01EF → byte values 16-255 (240 Supplementary VS codepoints)
//!
//! ## Decoding Algorithm
//!
//! ```text
//! for each char in input:
//!     if char in U+FE00..=U+FE0F:
//!         byte = (char as u32) - 0xFE00
//!         push byte to output buffer
//!     else if char in U+E0100..=U+E01EF:
//!         byte = (char as u32) - 0xE0100 + 16
//!         push byte to output buffer
//!     else:
//!         skip (not a VS codepoint)
//! ```

/// Classification of decoded payload based on entropy analysis
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PayloadClass {
    /// Entropy < 6.0, valid UTF-8 — likely plaintext code (Wave 0 style)
    PlaintextCode,
    /// Entropy > 7.0 — likely encrypted/compressed (Waves 1-3)
    EncryptedOrCompressed,
    /// Entropy 6.0-7.0 — suspicious, unclear
    SuspiciousData,
    /// Too few codepoints to classify (< 16 bytes decoded)
    TooSmall,
}

impl PayloadClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            PayloadClass::PlaintextCode => "plaintext_code",
            PayloadClass::EncryptedOrCompressed => "encrypted_or_compressed",
            PayloadClass::SuspiciousData => "suspicious_data",
            PayloadClass::TooSmall => "too_small",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            PayloadClass::PlaintextCode => "Likely plaintext code (Wave 0 style)",
            PayloadClass::EncryptedOrCompressed => "Likely encrypted or compressed (Waves 1-3)",
            PayloadClass::SuspiciousData => "Suspicious data with medium entropy",
            PayloadClass::TooSmall => "Too few codepoints to classify",
        }
    }
}

/// Result of decoding a steganographic payload
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DecodedPayload {
    /// Raw decoded bytes
    pub bytes: Vec<u8>,
    /// Shannon entropy of decoded bytes (0.0-8.0)
    pub entropy: f64,
    /// Whether bytes are valid UTF-8
    pub is_valid_utf8: bool,
    /// If valid UTF-8, the decoded text (for display)
    pub decoded_text: Option<String>,
    /// Classification based on entropy analysis
    pub payload_class: PayloadClass,
    /// Number of VS codepoints that were decoded
    pub codepoint_count: usize,
}

impl DecodedPayload {
    /// Get a hex preview of the first N bytes
    pub fn hex_preview(&self, max_bytes: usize) -> String {
        let bytes = if self.bytes.len() > max_bytes {
            &self.bytes[..max_bytes]
        } else {
            &self.bytes
        };
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Get the decoded text truncated to max_len characters
    pub fn text_preview(&self, max_len: usize) -> Option<String> {
        self.decoded_text.as_ref().map(|text| {
            if text.len() > max_len {
                format!("{}... ({} bytes total)", &text[..max_len], text.len())
            } else {
                text.clone()
            }
        })
    }
}

/// Decode VS stego from a string.
///
/// Returns None if fewer than 4 VS codepoints found (too small to be meaningful).
///
/// # Arguments
///
/// * `input` - The string containing encoded VS codepoints
///
/// # Returns
///
/// * `Some(DecodedPayload)` if 4+ VS codepoints found
/// * `None` if fewer than 4 VS codepoints
///
/// # Example
///
/// ```rust
/// use glassware_core::decoder::decode_vs_stego;
///
/// // Encode "test" manually:
/// // 't' = 0x74 = 116 → 116 - 16 = 100 → U+E0100 + 100 = U+E0164
/// // 'e' = 0x65 = 101 → 101 - 16 = 85 → U+E0100 + 85 = U+E0155
/// // 's' = 0x73 = 115 → 115 - 16 = 99 → U+E0100 + 99 = U+E0163
/// // 't' = 0x74 = 116 → 116 - 16 = 100 → U+E0100 + 100 = U+E0164
/// let encoded = format!("{}{}{}{}",
///     char::from_u32(0xE0164).unwrap(),
///     char::from_u32(0xE0155).unwrap(),
///     char::from_u32(0xE0163).unwrap(),
///     char::from_u32(0xE0164).unwrap()
/// );
/// let payload = decode_vs_stego(&encoded).unwrap();
/// assert_eq!(payload.decoded_text, Some("test".to_string()));
/// ```
pub fn decode_vs_stego(input: &str) -> Option<DecodedPayload> {
    let mut bytes = Vec::new();
    let mut codepoint_count = 0;

    for ch in input.chars() {
        let cp = ch as u32;
        let byte = if (0xFE00..=0xFE0F).contains(&cp) {
            // Primary Variation Selectors: 0-15
            (cp - 0xFE00) as u8
        } else if (0xE0100..=0xE01EF).contains(&cp) {
            // Supplementary Variation Selectors: 16-255
            (cp - 0xE0100 + 16) as u8
        } else {
            // Not a VS codepoint - skip
            continue;
        };

        bytes.push(byte);
        codepoint_count += 1;
    }

    // Too few codepoints to be meaningful
    if codepoint_count < 4 {
        return None;
    }

    let entropy = shannon_entropy(&bytes);
    let is_valid_utf8 = std::str::from_utf8(&bytes).is_ok();
    let decoded_text = if is_valid_utf8 {
        std::str::from_utf8(&bytes).ok().map(|s| s.to_string())
    } else {
        None
    };

    let payload_class = classify_payload(&bytes, entropy, is_valid_utf8);

    Some(DecodedPayload {
        bytes,
        entropy,
        is_valid_utf8,
        decoded_text,
        payload_class,
        codepoint_count,
    })
}

/// Calculate Shannon entropy of byte data
///
/// Returns a value between 0.0 (all same byte) and 8.0 (uniform distribution).
///
/// # Arguments
///
/// * `data` - The byte slice to analyze
///
/// # Returns
///
/// Shannon entropy in bits per byte
///
/// # Example
///
/// ```rust
/// use glassware_core::decoder::shannon_entropy;
///
/// // All same byte = 0 entropy
/// assert_eq!(shannon_entropy(&[0x41, 0x41, 0x41, 0x41]), 0.0);
///
/// // Random-ish data = high entropy
/// let entropy = shannon_entropy(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
/// assert!(entropy > 2.5);
/// ```
pub fn shannon_entropy(data: &[u8]) -> f64 {
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

/// Classify payload based on entropy and UTF-8 validity
fn classify_payload(bytes: &[u8], entropy: f64, is_valid_utf8: bool) -> PayloadClass {
    if bytes.len() < 16 {
        return PayloadClass::TooSmall;
    }

    if entropy > 7.0 {
        PayloadClass::EncryptedOrCompressed
    } else if entropy >= 6.0 {
        PayloadClass::SuspiciousData
    } else if is_valid_utf8 {
        PayloadClass::PlaintextCode
    } else {
        PayloadClass::SuspiciousData
    }
}

/// Check if a character is a Variation Selector codepoint used in stego
#[inline]
pub fn is_vs_codepoint(ch: char) -> bool {
    let cp = ch as u32;
    (0xFE00..=0xFE0F).contains(&cp) || (0xE0100..=0xE01EF).contains(&cp)
}

/// Count VS codepoints in a string
pub fn count_vs_codepoints(input: &str) -> usize {
    input.chars().filter(|&ch| is_vs_codepoint(ch)).count()
}

/// Find runs of VS codepoints in content
///
/// Returns Vec of (start_byte_offset, end_byte_offset, codepoint_count)
pub fn find_vs_runs(input: &str, min_run_length: usize) -> Vec<(usize, usize, usize)> {
    let mut runs = Vec::new();
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut i = 0;

    while i < chars.len() {
        let (start_offset, ch) = chars[i];
        if is_vs_codepoint(ch) {
            let run_start = start_offset;
            let mut run_end = start_offset + ch.len_utf8();
            let mut codepoint_count = 1;

            // Continue while we see VS codepoints
            let mut j = i + 1;
            while j < chars.len() {
                let (_, next_ch) = chars[j];
                if is_vs_codepoint(next_ch) {
                    run_end = chars[j].0 + next_ch.len_utf8();
                    codepoint_count += 1;
                    j += 1;
                } else {
                    break;
                }
            }

            if codepoint_count >= min_run_length {
                runs.push((run_start, run_end, codepoint_count));
            }

            i = j;
        } else {
            i += 1;
        }
    }

    runs
}

/// Encode bytes as VS codepoints (for testing)
#[cfg(test)]
pub fn encode_vs_stego(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&byte| {
            let cp = if byte < 16 {
                0xFE00 + byte as u32
            } else {
                0xE0100 + (byte as u32 - 16)
            };
            char::from_u32(cp).unwrap()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_known_payload() {
        // Encode "hello" (0x68, 0x65, 0x6C, 0x6C, 0x6F)
        // 'h' = 0x68 = 104 → 104 >= 16 → 104 - 16 = 88 → U+E0100 + 88 = U+E0158
        // 'e' = 0x65 = 101 → 101 - 16 = 85 → U+E0155
        // 'l' = 0x6C = 108 → 108 - 16 = 92 → U+E015C
        // 'l' = 0x6C = 108 → U+E015C
        // 'o' = 0x6F = 111 → 111 - 16 = 95 → U+E015F
        let encoded = encode_vs_stego(b"hello");
        let payload = decode_vs_stego(&encoded).unwrap();

        assert_eq!(payload.bytes, b"hello");
        assert_eq!(payload.decoded_text, Some("hello".to_string()));
        assert!(payload.is_valid_utf8);
        assert_eq!(payload.codepoint_count, 5);
    }

    #[test]
    fn test_decode_high_entropy() {
        // Generate 256 bytes with high entropy (all unique values)
        let bytes: Vec<u8> = (0..=255).collect();
        let encoded = encode_vs_stego(&bytes);
        let payload = decode_vs_stego(&encoded).unwrap();

        assert_eq!(payload.bytes.len(), 256);
        assert!(payload.entropy > 7.9); // Near maximum entropy
        assert_eq!(payload.payload_class, PayloadClass::EncryptedOrCompressed);
        assert!(!payload.is_valid_utf8);
    }

    #[test]
    fn test_decode_low_entropy_plaintext() {
        // Encode repetitive plaintext
        let text = "console.log('pwned'); console.log('pwned');";
        let encoded = encode_vs_stego(text.as_bytes());
        let payload = decode_vs_stego(&encoded).unwrap();

        assert_eq!(payload.decoded_text, Some(text.to_string()));
        assert!(payload.is_valid_utf8);
        assert!(payload.entropy < 6.0);
        assert_eq!(payload.payload_class, PayloadClass::PlaintextCode);
    }

    #[test]
    fn test_too_small_payload() {
        // Only 3 codepoints - should return None
        let encoded = encode_vs_stego(b"abc");
        let payload = decode_vs_stego(&encoded);
        assert!(payload.is_none());
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        // All same byte = 0 entropy
        assert_eq!(shannon_entropy(&[0x41, 0x41, 0x41, 0x41]), 0.0);
    }

    #[test]
    fn test_shannon_entropy_varied() {
        // Different bytes = higher entropy
        let entropy = shannon_entropy(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert!(entropy > 2.5);
    }

    #[test]
    fn test_is_vs_codepoint() {
        assert!(is_vs_codepoint('\u{FE00}'));
        assert!(is_vs_codepoint('\u{FE0F}'));
        assert!(is_vs_codepoint('\u{E0100}'));
        assert!(is_vs_codepoint('\u{E01EF}'));
        assert!(!is_vs_codepoint('A'));
        assert!(!is_vs_codepoint('\u{200B}'));
    }

    #[test]
    fn test_count_vs_codepoints() {
        let text = format!("Hello{}World{}Test", '\u{FE00}', '\u{E0100}');
        assert_eq!(count_vs_codepoints(&text), 2);
    }

    #[test]
    fn test_find_vs_runs() {
        // Create a run of 20 VS codepoints
        let vs_run: String = (0..20)
            .map(|i| char::from_u32(0xFE00 + (i % 16)).unwrap())
            .collect();
        let content = format!("visible code{}more code", vs_run);

        let runs = find_vs_runs(&content, 16);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].2, 20); // 20 codepoints
    }

    #[test]
    fn test_find_vs_runs_below_threshold() {
        // Create a run of only 5 VS codepoints
        let vs_run: String = (0..5)
            .map(|i| char::from_u32(0xFE00 + (i % 16)).unwrap())
            .collect();
        let content = format!("visible{}code", vs_run);

        let runs = find_vs_runs(&content, 16);
        assert!(runs.is_empty());
    }

    #[test]
    fn test_hex_preview() {
        let bytes = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let payload = DecodedPayload {
            bytes,
            entropy: 2.0,
            is_valid_utf8: false,
            decoded_text: None,
            payload_class: PayloadClass::TooSmall,
            codepoint_count: 6,
        };

        assert_eq!(payload.hex_preview(4), "00 01 02 03");
        assert_eq!(payload.hex_preview(10), "00 01 02 03 04 05");
    }

    #[test]
    fn test_payload_class_classification() {
        // Low entropy UTF-8 - need at least 16 bytes
        let payload = decode_vs_stego(&encode_vs_stego(b"hello world hello!")).unwrap();
        assert_eq!(payload.payload_class, PayloadClass::PlaintextCode);

        // High entropy
        let bytes: Vec<u8> = (0..=255).collect();
        let payload = decode_vs_stego(&encode_vs_stego(&bytes)).unwrap();
        assert_eq!(payload.payload_class, PayloadClass::EncryptedOrCompressed);
    }
}
