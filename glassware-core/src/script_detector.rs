//! Script Detector Module
//!
//! Detects Unicode script mixing in identifiers to identify potential homoglyph attacks
//! while allowing legitimate non-Latin identifiers (i18n, mathematical notation).
//!
//! ## Key Insight
//!
//! Pure non-Latin identifiers (e.g., Greek "μήνυμα", Cyrillic "сообщение") are legitimate
//! for i18n purposes. However, MIXED scripts within a single identifier (e.g., "variαble"
//! where α is Greek) indicates a potential homoglyph attack.

use unicode_script::{Script, UnicodeScript};

/// Detect which Unicode script a character belongs to
pub fn get_script(ch: char) -> Script {
    ch.script()
}

/// Check if an identifier contains mixed scripts (potential homoglyph attack)
///
/// Returns true if:
/// - The identifier contains both Latin (ASCII) AND non-Latin scripts
/// - This mixing is deceptive and indicates a potential attack
pub fn has_mixed_scripts(identifier: &str) -> bool {
    let mut non_latin_scripts = std::collections::HashSet::new();
    let mut has_latin = false;

    for ch in identifier.chars() {
        // Track ASCII Latin characters (but NOT underscore - it's common across scripts)
        if ch.is_ascii_alphabetic() {
            has_latin = true;
            continue;
        }

        // Skip common characters (underscore, digits, etc.)
        if ch == '_' || ch.is_ascii_digit() {
            continue;
        }

        let script = get_script(ch);

        // Only count non-Latin scripts
        if script != Script::Latin && script != Script::Common && script != Script::Inherited {
            non_latin_scripts.insert(script);
        }
    }

    // Mixed scripts = has Latin + 1+ non-Latin scripts
    has_latin && !non_latin_scripts.is_empty()
}

/// Check if identifier is pure non-Latin script (legitimate i18n)
///
/// Returns true if:
/// - The identifier contains non-Latin scripts
/// - The identifier does NOT contain any Latin ASCII characters
/// - This is legitimate for i18n, math notation, etc.
pub fn is_pure_non_latin(identifier: &str) -> bool {
    // Check for actual Latin letters (not underscore or digits)
    let has_latin = identifier.chars().any(|c| c.is_ascii_alphabetic());
    let has_non_latin = identifier.chars().any(|c| {
        let script = get_script(c);
        script != Script::Latin && script != Script::Common && script != Script::Inherited
    });

    // Pure non-Latin = has non-Latin but NO Latin letters
    has_non_latin && !has_latin
}

/// Check if identifier is pure Latin (no flags needed)
pub fn is_pure_latin(identifier: &str) -> bool {
    identifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Get all scripts present in an identifier
pub fn get_scripts_in_identifier(identifier: &str) -> Vec<Script> {
    let mut scripts = std::collections::HashSet::new();

    for ch in identifier.chars() {
        let script = get_script(ch);
        if script != Script::Common && script != Script::Inherited {
            scripts.insert(script);
        }
    }

    scripts.into_iter().collect()
}

/// Check if a character is from a high-risk script (commonly used in attacks)
pub fn is_high_risk_script(ch: char) -> bool {
    let script = get_script(ch);
    // Cyrillic and Greek are most commonly used in homoglyph attacks
    script == Script::Cyrillic || script == Script::Greek
}

/// Get the script name as a string for reporting
pub fn script_to_string(script: Script) -> &'static str {
    match script {
        Script::Latin => "Latin",
        Script::Cyrillic => "Cyrillic",
        Script::Greek => "Greek",
        Script::Arabic => "Arabic",
        Script::Hebrew => "Hebrew",
        Script::Han => "Han",
        Script::Hiragana => "Hiragana",
        Script::Katakana => "Katakana",
        Script::Hangul => "Hangul",
        Script::Thai => "Thai",
        Script::Devanagari => "Devanagari",
        Script::Common => "Common",
        Script::Inherited => "Inherited",
        _ => "Other",
    }
}

/// Extract identifiers from a line of code using simple heuristics
pub fn extract_identifiers(line: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let mut current = String::new();

    for ch in line.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            current.push(ch);
        } else {
            if !current.is_empty() && current.len() > 1 {
                identifiers.push(current.clone());
            }
            current.clear();
        }
    }

    if !current.is_empty() && current.len() > 1 {
        identifiers.push(current);
    }

    identifiers
}

/// Find which identifier contains a given character position (simplified implementation)
pub fn find_identifier_at_position(
    line: &str,
    char_pos: usize,
    _identifiers: &[String],
) -> Option<String> {
    // Simple approach: check if position is within any identifier
    // This is a simplified version - a full implementation would track positions

    let chars: Vec<char> = line.chars().collect();
    let _pos = 0;
    let mut in_identifier = false;
    let mut identifier_start = 0;

    for (i, &ch) in chars.iter().enumerate() {
        if ch.is_alphanumeric() || ch == '_' {
            if !in_identifier {
                in_identifier = true;
                identifier_start = i;
            }
        } else {
            if in_identifier && i - identifier_start > 1 {
                let ident: String = chars[identifier_start..i].iter().collect();
                if identifier_start <= char_pos && char_pos < i {
                    return Some(ident);
                }
            }
            in_identifier = false;
        }
    }

    // Check last identifier
    if in_identifier && chars.len() - identifier_start > 1 {
        let ident: String = chars[identifier_start..].iter().collect();
        if identifier_start <= char_pos && char_pos < chars.len() {
            return Some(ident);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mixed_scripts_cyrillic_a() {
        // "password" with Cyrillic 'а'
        assert!(has_mixed_scripts("pаssword"));
    }

    #[test]
    fn test_pure_cyrillic() {
        // Pure Cyrillic - legitimate
        assert!(is_pure_non_latin("сообщение"));
        assert!(!has_mixed_scripts("сообщение"));
    }

    #[test]
    fn test_pure_greek() {
        // Pure Greek - legitimate
        assert!(is_pure_non_latin("μήνυμα"));
        assert!(!has_mixed_scripts("μήνυμα"));
    }

    #[test]
    fn test_pure_latin() {
        assert!(is_pure_latin("password"));
        assert!(is_pure_latin("my_variable"));
    }

    #[test]
    fn test_extract_identifiers() {
        let line = "const password = 'secret';";
        let idents = extract_identifiers(line);
        assert!(idents.contains(&"const".to_string()));
        assert!(idents.contains(&"password".to_string()));
        assert!(idents.contains(&"secret".to_string()));
    }
}
