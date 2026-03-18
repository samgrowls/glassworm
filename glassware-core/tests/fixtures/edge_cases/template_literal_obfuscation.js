// EDGE CASE TEST FIXTURE — Template literal obfuscation
// Uses template literals to construct API names
// May evade regex detection - KNOWN LIMITATION

const crypto = require('crypto');

// Construct method name via template literal
const methodName = `cr${'eate'}Deciph${'eriv'}`;

// Hardcoded key
const secretKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ivHex = 'BBBBBBBBBBBBBBBB';

// Encrypted payload
const encryptedPayload = '4a6f686e446f65313233343536373839304142434445463031323334353637383930';

// Use computed property access with obfuscated method name
const decipher = crypto[methodName]('aes-256-cbc', secretKey, ivHex);
let decrypted = decipher.update(encryptedPayload, 'hex', 'utf8');
decrypted += decipher.final('utf8');

// Execute
eval(decrypted);
