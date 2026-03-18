// EDGE CASE TEST FIXTURE — Renamed variables
// AES decrypt + eval pattern with renamed variables
// createDecipheriv called on aliased variable instead of direct crypto import
// Tests whether regex still catches it

const cryptoLib = require('crypto');
const decryptFunc = cryptoLib.createDecipheriv;

// Hardcoded key (using dummy values)
const secretKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ivHex = 'BBBBBBBBBBBBBBBB';

// Encrypted payload (hex-encoded dummy data)
const encryptedPayload = '4a6f686e446f6531323334353637383930414243444546303132333435363738393041424344454630313233343536373839304142434445463031323334353637383930';

// Use aliased function instead of direct crypto.createDecipheriv
const decipher = decryptFunc('aes-256-cbc', secretKey, ivHex);
let decrypted = decipher.update(encryptedPayload, 'hex', 'utf8');
decrypted += decipher.final('utf8');

// Execute decrypted payload
eval(decrypted);
