// EDGE CASE TEST FIXTURE — Indirect eval reference
// Eval aliased to a variable before use
// Tests whether detection catches indirect eval

const crypto = require('crypto');

// Alias eval to a different variable name
const execute = eval;
const globalEval = (0, eval);

// High-entropy base64 payload
const payload = "VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHBheWxvYWQgdGhhdCBpcyBsb25nIGVub3VnaCB0byB0cmlnZ2VyIGRldGVjdGlvbi4gVGhlIGV2YWwgZnVuY3Rpb24gaXMgYWxpYXNlZCB0byBhdm9pZCBkaXJlY3QgZGV0ZWN0aW9uLg==";

// Execute via aliased eval
execute(atob(payload));

// Execute via IIFE-style eval
globalEval(atob(payload));

// Another alias pattern
const e = eval;
e(Buffer.from('YW5vdGhlciBwYXlsb2FkIHRoYXQgaXMgbG9uZyBlbm91Z2ggdG8gdHJpZ2dlciBkZXRlY3Rpb24gYW5kIHNob3VsZCBiZSBmbGFnZ2VkIGJ5IHRoZSBzY2FubmVy', 'base64').toString('utf-8'));
