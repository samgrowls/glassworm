// FALSE POSITIVE TEST FIXTURE — Legitimate i18n locale detection
// This file should produce ZERO findings
// Pattern: Locale checking for internationalization purposes
// Similar pattern to Russian locale gating but used for legitimate localization

/**
 * Detect user's preferred language for i18n
 * Uses standard Intl API for locale detection
 */
function getUserLocale() {
    // Browser environment
    if (typeof navigator !== 'undefined') {
        return navigator.language || navigator.userLanguage;
    }
    
    // Node.js environment
    if (typeof Intl !== 'undefined') {
        return Intl.DateTimeFormat().resolvedOptions().locale;
    }
    
    return 'en-US'; // Default
}

/**
 * Get language code from locale
 */
function getLanguageCode(locale) {
    return locale.split('-')[0].toLowerCase();
}

/**
 * Check if user prefers a specific language
 */
function prefersLanguage(locale, language) {
    return getLanguageCode(locale) === language.toLowerCase();
}

/**
 * Load translations based on user locale
 */
async function loadTranslations(locale) {
    const language = getLanguageCode(locale);
    
    // Supported languages
    const supportedLanguages = ['en', 'es', 'fr', 'de', 'ja', 'zh', 'ru'];
    
    // Fall back to English if language not supported
    const langToLoad = supportedLanguages.includes(language) ? language : 'en';
    
    // Fetch translations
    const response = await fetch(`/locales/${langToLoad}.json`);
    if (!response.ok) {
        throw new Error('Failed to load translations');
    }
    
    return response.json();
}

/**
 * Format date according to user locale
 */
function formatDate(date, locale) {
    return new Intl.DateTimeFormat(locale, {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    }).format(date);
}

/**
 * Format number according to user locale
 */
function formatNumber(number, locale) {
    return new Intl.NumberFormat(locale).format(number);
}

/**
 * Format currency according to user locale
 */
function formatCurrency(amount, locale, currency = 'USD') {
    return new Intl.NumberFormat(locale, {
        style: 'currency',
        currency
    }).format(amount);
}

/**
 * Initialize internationalization
 */
async function initI18n() {
    const locale = getUserLocale();
    const translations = await loadTranslations(locale);
    
    // Apply translations to page
    document.querySelectorAll('[data-i18n]').forEach(element => {
        const key = element.getAttribute('data-i18n');
        if (translations[key]) {
            element.textContent = translations[key];
        }
    });
    
    // Store current locale for future use
    document.documentElement.lang = locale;
    
    return { locale, translations };
}

// Example usage
const locale = getUserLocale();
console.log('User locale:', locale);
console.log('Prefers Russian:', prefersLanguage(locale, 'ru'));
console.log('Prefers English:', prefersLanguage(locale, 'en'));

// Format examples
const now = new Date();
console.log('Date (de-DE):', formatDate(now, 'de-DE'));
console.log('Number (de-DE):', formatNumber(1234567.89, 'de-DE'));
console.log('Currency (ja-JP):', formatCurrency(1234.56, 'ja-JP', 'JPY'));

module.exports = {
    getUserLocale,
    getLanguageCode,
    prefersLanguage,
    loadTranslations,
    formatDate,
    formatNumber,
    formatCurrency,
    initI18n
};
