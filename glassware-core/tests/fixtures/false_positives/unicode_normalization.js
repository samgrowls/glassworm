// FALSE POSITIVE TEST FIXTURE — Legitimate Unicode normalization
// This file should produce ZERO findings
// Pattern: Standard Unicode normalization APIs for text processing
// NO eval, NO Buffer.from → eval chain, NO codePointAt patterns

/**
 * Normalize Unicode text to NFC form
 * Uses standard String.normalize() API
 */
function normalizeText(text) {
    return text.normalize('NFC');
}

/**
 * Normalize Unicode text to NFKC form (compatibility)
 */
function normalizeCompatibility(text) {
    return text.normalize('NFKC');
}

/**
 * Get character code using charCodeAt (standard API)
 */
function getCharCode(char) {
    return char.charCodeAt(0);
}

/**
 * Detect if text contains emoji using regex
 */
function containsEmoji(text) {
    const emojiRegex = /[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}]/u;
    return emojiRegex.test(text);
}

/**
 * Count emoji in text using regex
 */
function countEmoji(text) {
    const emojiRegex = /[\u{1F300}-\u{1F9FF}]/ug;
    const matches = text.match(emojiRegex);
    return matches ? matches.length : 0;
}

/**
 * Convert text to ASCII approximation
 * Simple normalization for search indexing
 */
function toAsciiApprox(text) {
    const normalized = text.normalize('NFD');
    return normalized.replace(/[\u0300-\u036f]/g, '');
}

/**
 * Check if string contains only ASCII characters
 */
function isAscii(str) {
    return /^[\x00-\x7F]*$/.test(str);
}

// Example usage
const text = 'Hello, 世界！Привет! 👋';
console.log('Normalized:', normalizeText(text));
console.log('Has emoji:', containsEmoji(text));
console.log('Emoji count:', countEmoji('😀😂❤️'));
console.log('Is ASCII:', isAscii('Hello'));

module.exports = {
    normalizeText,
    normalizeCompatibility,
    getCharCode,
    containsEmoji,
    countEmoji,
    toAsciiApprox,
    isAscii
};
