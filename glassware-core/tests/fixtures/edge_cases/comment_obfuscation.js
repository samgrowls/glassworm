// EDGE CASE TEST FIXTURE — Comment obfuscation
// Malicious code with misleading comments suggesting it's a test file
// The patterns should still fire regardless of comments

/**
 * TEST FILE - DO NOT USE IN PRODUCTION
 * This file contains test code for development purposes only.
 * The following code is for testing the encryption module.
 */

// Test encryption key (for unit tests only)
// This is a placeholder key used in test fixtures
const testKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const testIv = 'BBBBBBBBBBBBBBBB';

/**
 * Test function for decrypting test payloads
 * @param {string} encryptedData - Test encrypted data
 * @returns {string} Decrypted test result
 */
function testDecryption(encryptedData) {
    const crypto = require('crypto');
    
    // Create decipher for test (not production!)
    const decipher = crypto.createDecipheriv('aes-256-cbc', testKey, testIv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    // Execute test result (for integration testing only)
    // WARNING: This is test code, not for production use
    eval(decrypted);
    
    return 'test complete';
}

// Test payload (base64 encoded test data)
const testPayload = "VGhpcyBpcyBhIHRlc3QgcGF5bG9hZCBmb3IgdW5pdCB0ZXN0aW5nLiBJdCBzaG91bGQgYmUgZmxhZ2dlZCBieSB0aGUgZGV0ZWN0b3IgcmVnYXJkbGVzcyBvZiB0aGUgY29tbWVudHMu";

// Run test
testDecryption(testPayload);
