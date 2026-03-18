//! Codepoint Classification
//!
//! This module provides functions for classifying Unicode code points
//! as invisible, bidirectional, zero-width, etc.

pub use crate::ranges::{
    get_bidi_name, get_zero_width_name, is_in_critical_range, is_in_invisible_range,
    is_variation_selector, BidiChar, InvisibleRange, ZeroWidthChar,
};

/// Check if a code point is an invisible character
pub fn is_invisible(code_point: u32) -> bool {
    is_in_invisible_range(code_point)
}

/// Check if a code point is a bidirectional control character
pub fn is_bidi(code_point: u32) -> bool {
    get_bidi_name(code_point).is_some()
}

/// Check if a code point is a zero-width character
pub fn is_zero_width(code_point: u32) -> bool {
    get_zero_width_name(code_point).is_some()
}

/// Check if a code point is critical (high severity)
pub fn is_critical(code_point: u32) -> bool {
    is_in_critical_range(code_point)
}

/// Get the severity level for a code point
pub fn get_severity(code_point: u32) -> &'static str {
    if is_critical(code_point) || is_variation_selector(code_point) {
        "critical"
    } else if is_bidi(code_point) || is_zero_width(code_point) {
        "high"
    } else {
        "medium"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_invisible() {
        assert!(is_invisible(0xFE00));
        assert!(is_invisible(0x200B));
        assert!(!is_invisible(0x0041));
    }

    #[test]
    fn test_is_bidi() {
        assert!(is_bidi(0x202E));
        assert!(is_bidi(0x202A));
        assert!(!is_bidi(0x0041));
    }

    #[test]
    fn test_is_zero_width() {
        assert!(is_zero_width(0x200B));
        assert!(is_zero_width(0x200D));
        assert!(!is_zero_width(0x0041));
    }

    #[test]
    fn test_is_critical() {
        assert!(is_critical(0xFE00));
        assert!(is_critical(0x202E));
        assert!(!is_critical(0xE0000));
    }
}
