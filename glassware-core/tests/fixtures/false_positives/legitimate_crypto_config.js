// FALSE POSITIVE TEST FIXTURE — Legitimate crypto with env-based keys
// This file should produce ZERO findings
// Pattern: Key from environment variable, not hardcoded in source

const crypto = require('crypto');

/**
 * Configuration-based encryption using environment variables
 * Keys are loaded from environment, not hardcoded in source code
 */

// Key loaded from environment variable (secure pattern)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const ENCRYPTION_IV = process.env.ENCRYPTION_IV;

if (!ENCRYPTION_KEY || !ENCRYPTION_IV) {
    throw new Error('ENCRYPTION_KEY and ENCRYPTION_IV must be set in environment');
}

// Convert key and IV to buffers
const key = Buffer.from(ENCRYPTION_KEY, 'utf8');
const iv = Buffer.from(ENCRYPTION_IV, 'hex');

/**
 * Create decipher for decrypting stored data
 * Uses key from environment - NOT hardcoded
 */
function createDecipher() {
    return crypto.createDecipheriv('aes-256-gcm', key, iv);
}

/**
 * Decrypt a stored value
 */
function decryptValue(encryptedHex) {
    const decipher = createDecipher();
    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

module.exports = { decryptValue, createDecipher };
