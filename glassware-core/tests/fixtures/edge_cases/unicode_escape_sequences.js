// EDGE CASE TEST FIXTURE — Unicode escape sequences
// Critical function names using Unicode escapes
// Tests whether detection catches \uXXXX encoded names

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

// Unicode escape for "eval" = \u0065\u0076\u0061\u006c
const evalFunc = eval;
evalFunc(decrypted);

// Another pattern: construct function name via escape sequences
const funcName = '\u0065\u0076\u0061\u006c'; // "eval"
global[funcName](decrypted);

// Template literal with escapes
const fn = `${'\u0065'}${'\u0076'}${'\u0061'}${'\u006c'}`;
global[fn](decrypted);
