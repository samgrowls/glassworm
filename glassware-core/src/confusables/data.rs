//! Confusables Data Module
//!
//! This module provides confusable character detection for homoglyph attacks.
//!
//! Data Source: Based on Unicode confusables data
//! This is a minimal subset focusing on the most common attack characters.

use std::collections::HashMap;
use std::sync::OnceLock;

/// A confusable character entry
#[derive(Debug, Clone)]
pub struct ConfusableEntry {
    pub confusable: char,
    pub base: char,
    pub script: &'static str,
    pub similarity: f32,
}

/// Get the confusables database (lazy initialization)
fn get_confusables_db() -> &'static HashMap<char, ConfusableEntry> {
    static CONFUSABLES_DB: OnceLock<HashMap<char, ConfusableEntry>> = OnceLock::new();
    CONFUSABLES_DB.get_or_init(|| {
        let mut map = HashMap::new();

        // Cyrillic confusables (most common attacks)
        // Cyrillic 'а' (U+0430) vs Latin 'a'
        map.insert(
            '\u{0430}',
            ConfusableEntry {
                confusable: '\u{0430}',
                base: 'a',
                script: "Cyrillic",
                similarity: 1.0,
            },
        );
        // Cyrillic 'е' (U+0435) vs Latin 'e'
        map.insert(
            '\u{0435}',
            ConfusableEntry {
                confusable: '\u{0435}',
                base: 'e',
                script: "Cyrillic",
                similarity: 1.0,
            },
        );
        // Cyrillic 'о' (U+043E) vs Latin 'o'
        map.insert(
            '\u{043E}',
            ConfusableEntry {
                confusable: '\u{043E}',
                base: 'o',
                script: "Cyrillic",
                similarity: 1.0,
            },
        );
        // Cyrillic 'р' (U+0440) vs Latin 'p'
        map.insert(
            '\u{0440}',
            ConfusableEntry {
                confusable: '\u{0440}',
                base: 'p',
                script: "Cyrillic",
                similarity: 1.0,
            },
        );
        // Cyrillic 'с' (U+0441) vs Latin 'c'
        map.insert(
            '\u{0441}',
            ConfusableEntry {
                confusable: '\u{0441}',
                base: 'c',
                script: "Cyrillic",
                similarity: 1.0,
            },
        );
        // Cyrillic 'х' (U+0445) vs Latin 'x'
        map.insert(
            '\u{0445}',
            ConfusableEntry {
                confusable: '\u{0445}',
                base: 'x',
                script: "Cyrillic",
                similarity: 1.0,
            },
        );
        // Cyrillic 'у' (U+0443) vs Latin 'y'
        map.insert(
            '\u{0443}',
            ConfusableEntry {
                confusable: '\u{0443}',
                base: 'y',
                script: "Cyrillic",
                similarity: 1.0,
            },
        );
        // Cyrillic 'А' (U+0410) vs Latin 'A'
        map.insert(
            '\u{0410}',
            ConfusableEntry {
                confusable: '\u{0410}',
                base: 'A',
                script: "Cyrillic",
                similarity: 1.0,
            },
        );
        // Cyrillic 'Е' (U+0415) vs Latin 'E'
        map.insert(
            '\u{0415}',
            ConfusableEntry {
                confusable: '\u{0415}',
                base: 'E',
                script: "Cyrillic",
                similarity: 1.0,
            },
        );
        // Cyrillic 'О' (U+041E) vs Latin 'O'
        map.insert(
            '\u{041E}',
            ConfusableEntry {
                confusable: '\u{041E}',
                base: 'O',
                script: "Cyrillic",
                similarity: 1.0,
            },
        );
        // Cyrillic 'Р' (U+0420) vs Latin 'P'
        map.insert(
            '\u{0420}',
            ConfusableEntry {
                confusable: '\u{0420}',
                base: 'P',
                script: "Cyrillic",
                similarity: 1.0,
            },
        );
        // Cyrillic 'С' (U+0421) vs Latin 'C'
        map.insert(
            '\u{0421}',
            ConfusableEntry {
                confusable: '\u{0421}',
                base: 'C',
                script: "Cyrillic",
                similarity: 1.0,
            },
        );
        // Cyrillic 'Х' (U+0425) vs Latin 'X'
        map.insert(
            '\u{0425}',
            ConfusableEntry {
                confusable: '\u{0425}',
                base: 'X',
                script: "Cyrillic",
                similarity: 1.0,
            },
        );
        // Cyrillic 'У' (U+0423) vs Latin 'Y'
        map.insert(
            '\u{0423}',
            ConfusableEntry {
                confusable: '\u{0423}',
                base: 'Y',
                script: "Cyrillic",
                similarity: 1.0,
            },
        );

        // Greek confusables
        // Greek 'α' (U+03B1) vs Latin 'a'
        map.insert(
            '\u{03B1}',
            ConfusableEntry {
                confusable: '\u{03B1}',
                base: 'a',
                script: "Greek",
                similarity: 0.95,
            },
        );
        // Greek 'ο' (U+03BF) vs Latin 'o'
        map.insert(
            '\u{03BF}',
            ConfusableEntry {
                confusable: '\u{03BF}',
                base: 'o',
                script: "Greek",
                similarity: 1.0,
            },
        );
        // Greek 'ι' (U+03B9) vs Latin 'i'
        map.insert(
            '\u{03B9}',
            ConfusableEntry {
                confusable: '\u{03B9}',
                base: 'i',
                script: "Greek",
                similarity: 0.9,
            },
        );
        // Greek 'Α' (U+0391) vs Latin 'A'
        map.insert(
            '\u{0391}',
            ConfusableEntry {
                confusable: '\u{0391}',
                base: 'A',
                script: "Greek",
                similarity: 1.0,
            },
        );
        // Greek 'Β' (U+0392) vs Latin 'B'
        map.insert(
            '\u{0392}',
            ConfusableEntry {
                confusable: '\u{0392}',
                base: 'B',
                script: "Greek",
                similarity: 1.0,
            },
        );
        // Greek 'Ε' (U+0395) vs Latin 'E'
        map.insert(
            '\u{0395}',
            ConfusableEntry {
                confusable: '\u{0395}',
                base: 'E',
                script: "Greek",
                similarity: 1.0,
            },
        );
        // Greek 'Ζ' (U+0396) vs Latin 'Z'
        map.insert(
            '\u{0396}',
            ConfusableEntry {
                confusable: '\u{0396}',
                base: 'Z',
                script: "Greek",
                similarity: 1.0,
            },
        );
        // Greek 'Η' (U+0397) vs Latin 'H'
        map.insert(
            '\u{0397}',
            ConfusableEntry {
                confusable: '\u{0397}',
                base: 'H',
                script: "Greek",
                similarity: 1.0,
            },
        );
        // Greek 'Ι' (U+0399) vs Latin 'I'
        map.insert(
            '\u{0399}',
            ConfusableEntry {
                confusable: '\u{0399}',
                base: 'I',
                script: "Greek",
                similarity: 1.0,
            },
        );
        // Greek 'Κ' (U+039A) vs Latin 'K'
        map.insert(
            '\u{039A}',
            ConfusableEntry {
                confusable: '\u{039A}',
                base: 'K',
                script: "Greek",
                similarity: 1.0,
            },
        );
        // Greek 'Μ' (U+039C) vs Latin 'M'
        map.insert(
            '\u{039C}',
            ConfusableEntry {
                confusable: '\u{039C}',
                base: 'M',
                script: "Greek",
                similarity: 1.0,
            },
        );
        // Greek 'Ν' (U+039D) vs Latin 'N'
        map.insert(
            '\u{039D}',
            ConfusableEntry {
                confusable: '\u{039D}',
                base: 'N',
                script: "Greek",
                similarity: 1.0,
            },
        );
        // Greek 'Ο' (U+039F) vs Latin 'O'
        map.insert(
            '\u{039F}',
            ConfusableEntry {
                confusable: '\u{039F}',
                base: 'O',
                script: "Greek",
                similarity: 1.0,
            },
        );
        // Greek 'Ρ' (U+03A1) vs Latin 'P'
        map.insert(
            '\u{03A1}',
            ConfusableEntry {
                confusable: '\u{03A1}',
                base: 'P',
                script: "Greek",
                similarity: 1.0,
            },
        );
        // Greek 'Τ' (U+03A4) vs Latin 'T'
        map.insert(
            '\u{03A4}',
            ConfusableEntry {
                confusable: '\u{03A4}',
                base: 'T',
                script: "Greek",
                similarity: 1.0,
            },
        );
        // Greek 'Χ' (U+03A7) vs Latin 'X'
        map.insert(
            '\u{03A7}',
            ConfusableEntry {
                confusable: '\u{03A7}',
                base: 'X',
                script: "Greek",
                similarity: 1.0,
            },
        );
        // Greek 'Υ' (U+03A5) vs Latin 'Y'
        map.insert(
            '\u{03A5}',
            ConfusableEntry {
                confusable: '\u{03A5}',
                base: 'Y',
                script: "Greek",
                similarity: 0.95,
            },
        );

        map
    })
}

/// Check if a character is confusable
pub fn is_confusable(ch: char) -> bool {
    get_confusables_db().contains_key(&ch)
}

/// Get the base character for a confusable
pub fn get_base_char(ch: char) -> Option<char> {
    get_confusables_db().get(&ch).map(|e| e.base)
}

/// Get the script of a confusable character
pub fn get_confusable_script(ch: char) -> Option<&'static str> {
    get_confusables_db().get(&ch).map(|e| e.script)
}

/// Get the similarity score for a confusable
pub fn get_similarity(ch: char) -> Option<f32> {
    get_confusables_db().get(&ch).map(|e| e.similarity)
}

/// Get all confusables that map to a given base character
pub fn get_confusables(base: char) -> Vec<ConfusableEntry> {
    get_confusables_db()
        .values()
        .filter(|e| e.base == base)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cyrillic_a() {
        assert!(is_confusable('\u{0430}')); // Cyrillic 'а'
        assert_eq!(get_base_char('\u{0430}'), Some('a'));
        assert_eq!(get_confusable_script('\u{0430}'), Some("Cyrillic"));
    }

    #[test]
    fn test_greek_o() {
        assert!(is_confusable('\u{03BF}')); // Greek 'ο'
        assert_eq!(get_base_char('\u{03BF}'), Some('o'));
        assert_eq!(get_confusable_script('\u{03BF}'), Some("Greek"));
    }

    #[test]
    fn test_latin_not_confusable() {
        assert!(!is_confusable('a'));
        assert!(!is_confusable('A'));
    }
}
