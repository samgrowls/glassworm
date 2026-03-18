// EDGE CASE TEST FIXTURE — Hex encoded strings
// Payload strings in hex encoding instead of base64
// Should still trigger on the eval sink

const crypto = require('crypto');

// Hex-encoded payload (represents "console.log('Hello')" in hex)
const hexPayload = "636f6e736f6c652e6c6f67282748656c6c6f27293b0a";

// Convert hex to string
function hexToString(hex) {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
}

// Execute the decoded payload
const decoded = hexToString(hexPayload);
eval(decoded);

// Another pattern: inline hex conversion
eval((function(h) {
    let s = '';
    for (let i = 0; i < h.length; i += 2) {
        s += String.fromCharCode(parseInt(h.substr(i, 2), 16));
    }
    return s;
})("616c657274282758535327293b"));
