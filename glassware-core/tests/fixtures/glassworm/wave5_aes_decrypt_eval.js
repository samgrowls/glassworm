// SANITIZED TEST FIXTURE — reconstructed from public IOCs for detection testing
// Wave 5: AES Decrypt + Eval Chain (Mar 2026)
// Source: Aikido "GlassWorm Strikes Popular React Native Phone Number Packages"
// Pattern: crypto.createDecipheriv + hardcoded key + eval

const crypto = require("crypto");

// Hardcoded encryption key (32 bytes for AES-256)
// SANITIZED: Using dummy values instead of real attacker keys
const secretKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 A's
const ivHex = "BBBBBBBBBBBBBBBB"; // 16 B's for 128-bit IV

// Encrypted payload (hex-encoded)
// SANITIZED: This is dummy hex data, not a real payload
const encryptedPayload = "4a6f686e446f6531323334353637383930414243444546303132333435363738393041424344454630313233343536373839304142434445463031323334353637383930414243444546303132333435363738393041424344454630313233343536373839304142434445463031323334353637383930";

// Decrypt using AES-256-CBC
const decipher = crypto.createDecipheriv("aes-256-cbc", secretKey, ivHex);
let decrypted = decipher.update(encryptedPayload, "hex", "utf8");
decrypted += decipher.final("utf8");

// Execute decrypted payload
eval(decrypted);

// Alternative pattern: new Function constructor
// const fn = new Function(decrypted);
// fn();
