// FALSE POSITIVE TEST FIXTURE — Legitimate crypto usage
// This file should produce ZERO findings
// Pattern: Normal encryption for user data at rest with runtime-generated keys

const crypto = require('crypto');

/**
 * Encrypts sensitive user data for storage
 * Key is generated at runtime via crypto.randomBytes (NOT hardcoded)
 */
function encryptUserData(data) {
    const algorithm = 'aes-256-cbc';
    
    // Key generated at runtime - NOT hardcoded
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Return encrypted data along with key and IV for decryption
    // (In production, key would be stored securely, e.g., in a KMS)
    return {
        encrypted,
        key: key.toString('hex'),
        iv: iv.toString('hex')
    };
}

/**
 * Decrypts user data using the provided key and IV
 */
function decryptUserData(encryptedData, keyHex, ivHex) {
    const algorithm = 'aes-256-cbc';
    const key = Buffer.from(keyHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}

// Example usage
const userData = { name: 'John Doe', email: 'john@example.com', ssn: '123-45-6789' };
const encrypted = encryptUserData(JSON.stringify(userData));
console.log('Encrypted:', encrypted);

const decrypted = decryptUserData(encrypted.encrypted, encrypted.key, encrypted.iv);
console.log('Decrypted:', JSON.parse(decrypted));
