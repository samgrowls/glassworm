// EDGE CASE TEST FIXTURE — Conditional eval
// Eval behind a conditional check
// Should still trigger detection

const crypto = require('crypto');

// Hardcoded key
const secretKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ivHex = 'BBBBBBBBBBBBBBBB';

// Encrypted payload
const encryptedPayload = '4a6f686e446f65313233343536373839304142434445463031323334353637383930';

// Decrypt
const decipher = crypto.createDecipheriv('aes-256-cbc', secretKey, ivHex);
let decrypted = decipher.update(encryptedPayload, 'hex', 'utf8');
decrypted += decipher.final('utf8');

// Conditional execution - should still be detected
if (process.env.NODE_ENV === 'production') {
    eval(decrypted);
}

// Another conditional pattern
if (typeof window !== 'undefined') {
    eval(decrypted);
}

// Ternary pattern
process.env.DEBUG ? console.log(decrypted) : eval(decrypted);
