//! Unicode Range Definitions
//!
//! This module defines the Unicode ranges used for attack detection.

/// A named Unicode range
#[derive(Debug, Clone)]
pub struct InvisibleRange {
    /// Start of the range (inclusive)
    pub start: u32,
    /// End of the range (inclusive)
    pub end: u32,
    /// Name of the range
    pub name: &'static str,
    /// Description of the range
    pub description: &'static str,
}

impl InvisibleRange {
    /// Create a new invisible range
    pub const fn new(start: u32, end: u32, name: &'static str, description: &'static str) -> Self {
        Self {
            start,
            end,
            name,
            description,
        }
    }

    /// Check if a code point is within this range
    pub fn contains(&self, code_point: u32) -> bool {
        code_point >= self.start && code_point <= self.end
    }
}

/// A named bidi character
#[derive(Debug, Clone, Copy)]
pub struct BidiChar {
    /// Unicode code point value
    pub code_point: u32,
    /// Name of the bidi character
    pub name: &'static str,
}

impl BidiChar {
    /// Create a new bidi character entry
    pub const fn new(code_point: u32, name: &'static str) -> Self {
        Self { code_point, name }
    }
}

/// A named zero-width character
#[derive(Debug, Clone, Copy)]
pub struct ZeroWidthChar {
    /// Unicode code point value
    pub code_point: u32,
    /// Name of the zero-width character
    pub name: &'static str,
}

impl ZeroWidthChar {
    /// Create a new zero-width character entry
    pub const fn new(code_point: u32, name: &'static str) -> Self {
        Self { code_point, name }
    }
}

// Variation Selectors (Glassware primary range)
pub const VARIATION_SELECTORS: InvisibleRange = InvisibleRange::new(
    0xFE00,
    0xFE0F,
    "Variation Selectors",
    "Used by Glassware to hide payloads",
);

// Variation Selectors Supplement
pub const VARIATION_SELECTORS_SUPPLEMENT: InvisibleRange = InvisibleRange::new(
    0xE0100,
    0xE01EF,
    "Variation Selectors Supplement",
    "Extended variation selectors",
);

// Zero-width characters
pub const ZERO_WIDTH_SPACE: InvisibleRange = InvisibleRange::new(
    0x200B,
    0x200F,
    "Zero-Width Characters",
    "Invisible characters used for injection attacks",
);

// Word joiner and invisible operators
pub const INVISIBLE_OPERATORS: InvisibleRange = InvisibleRange::new(
    0x2060,
    0x206F,
    "Invisible Operators",
    "Hidden formatting characters",
);

// Bidirectional overrides
pub const BIDIRECTIONAL_FORMATTING: InvisibleRange = InvisibleRange::new(
    0x202A,
    0x202E,
    "Bidirectional Formatting",
    "Text direction override characters",
);

// Isolation characters
pub const ISOLATION_CHARACTERS: InvisibleRange = InvisibleRange::new(
    0x2066,
    0x2069,
    "Isolation Characters",
    "Unicode isolation formatting",
);

// Unicode tags
pub const UNICODE_TAGS: InvisibleRange = InvisibleRange::new(
    0xE0000,
    0xE007F,
    "Unicode Tags",
    "Tag characters for metadata injection",
);

// Specials
pub const SPECIALS: InvisibleRange =
    InvisibleRange::new(0xFFF0, 0xFFFF, "Specials", "Special purpose characters");

/// All invisible character ranges
pub const INVISIBLE_RANGES: &[InvisibleRange] = &[
    VARIATION_SELECTORS,
    VARIATION_SELECTORS_SUPPLEMENT,
    ZERO_WIDTH_SPACE,
    INVISIBLE_OPERATORS,
    BIDIRECTIONAL_FORMATTING,
    ISOLATION_CHARACTERS,
    UNICODE_TAGS,
    SPECIALS,
];

/// Critical ranges (always scan regardless of sensitivity)
pub const CRITICAL_RANGES: &[InvisibleRange] = &[
    VARIATION_SELECTORS,
    VARIATION_SELECTORS_SUPPLEMENT,
    ZERO_WIDTH_SPACE,
    BIDIRECTIONAL_FORMATTING,
];

/// Bidirectional control characters
pub const BIDI_CHARS: &[BidiChar] = &[
    BidiChar::new(0x202A, "LRE"), // Left-to-Right Embedding
    BidiChar::new(0x202B, "RLE"), // Right-to-Left Embedding
    BidiChar::new(0x202C, "PDF"), // Pop Directional Formatting
    BidiChar::new(0x202D, "LRO"), // Left-to-Right Override
    BidiChar::new(0x202E, "RLO"), // Right-to-Left Override (MOST DANGEROUS)
    BidiChar::new(0x2066, "LRI"), // Left-to-Right Isolate
    BidiChar::new(0x2067, "RLI"), // Right-to-Left Isolate
    BidiChar::new(0x2068, "FSI"), // First Strong Isolate
    BidiChar::new(0x2069, "PDI"), // Pop Directional Isolate
    BidiChar::new(0x200E, "LRM"), // Left-to-Right Mark
    BidiChar::new(0x200F, "RLM"), // Right-to-Left Mark
    BidiChar::new(0x061C, "ALM"), // Arabic Letter Mark
];

/// Zero-width characters
pub const ZERO_WIDTH_CHARS: &[ZeroWidthChar] = &[
    ZeroWidthChar::new(0x200B, "ZWSP"), // Zero Width Space
    ZeroWidthChar::new(0x200C, "ZWNJ"), // Zero Width Non-Joiner
    ZeroWidthChar::new(0x200D, "ZWJ"),  // Zero Width Joiner
    ZeroWidthChar::new(0x2060, "WJ"),   // Word Joiner
    ZeroWidthChar::new(0xFEFF, "BOM"),  // Byte Order Mark (when not at start)
];

/// Check if a code point is in any invisible range
pub fn is_in_invisible_range(code_point: u32) -> bool {
    INVISIBLE_RANGES.iter().any(|r| r.contains(code_point))
}

/// Check if a code point is in a critical range (highest severity)
pub fn is_in_critical_range(code_point: u32) -> bool {
    CRITICAL_RANGES.iter().any(|r| r.contains(code_point))
}

/// Get the name of a bidirectional character if it is one
pub fn get_bidi_name(code_point: u32) -> Option<&'static str> {
    BIDI_CHARS
        .iter()
        .find(|b| b.code_point == code_point)
        .map(|b| b.name)
}

/// Get the name of a zero-width character if it is one
pub fn get_zero_width_name(code_point: u32) -> Option<&'static str> {
    ZERO_WIDTH_CHARS
        .iter()
        .find(|z| z.code_point == code_point)
        .map(|z| z.name)
}

/// Check if a code point is a variation selector (used in Glassware attacks)
pub fn is_variation_selector(code_point: u32) -> bool {
    (0xFE00..=0xFE0F).contains(&code_point) || (0xE0100..=0xE01EF).contains(&code_point)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variation_selector_range() {
        assert!(VARIATION_SELECTORS.contains(0xFE00));
        assert!(VARIATION_SELECTORS.contains(0xFE0F));
        assert!(!VARIATION_SELECTORS.contains(0xFE10));
    }

    #[test]
    fn test_is_in_invisible_range() {
        assert!(is_in_invisible_range(0xFE00));
        assert!(is_in_invisible_range(0x200B));
        assert!(is_in_invisible_range(0x202E));
        assert!(!is_in_invisible_range(0x0041));
    }

    #[test]
    fn test_is_in_critical_range() {
        assert!(is_in_critical_range(0xFE00));
        assert!(is_in_critical_range(0x200B));
        assert!(is_in_critical_range(0x202E));
        assert!(!is_in_critical_range(0xE0000));
    }

    #[test]
    fn test_bidi_names() {
        assert_eq!(get_bidi_name(0x202E), Some("RLO"));
        assert_eq!(get_bidi_name(0x202A), Some("LRE"));
        assert_eq!(get_bidi_name(0x0041), None);
    }

    #[test]
    fn test_variation_selector_detection() {
        assert!(is_variation_selector(0xFE00));
        assert!(is_variation_selector(0xFE0F));
        assert!(is_variation_selector(0xE0100));
        assert!(!is_variation_selector(0x200B));
    }
}
