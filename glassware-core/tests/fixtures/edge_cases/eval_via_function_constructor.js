// EDGE CASE TEST FIXTURE — Eval via Function constructor
// Uses Function constructor instead of eval()
// Should still trigger detection

const crypto = require('crypto');

// High-entropy base64 payload
const payload = "VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHBheWxvYWQgdGhhdCBpcyBsb25nIGVub3VnaCB0byB0cmlnZ2VyIGRldGVjdGlvbi4gSXQgcmVwcmVzZW50cyBhbiBlbmNyeXB0ZWQgb3Igb2JmdXNjYXRlZCBtYWxpY2lvdXMgcGF5bG9hZC4=";

// Decode the payload
const decoded = atob(payload);

// Execute via Function constructor instead of eval
const fn = new Function(decoded);
fn();

// Alternative pattern: immediately invoke
new Function(atob(payload))();
