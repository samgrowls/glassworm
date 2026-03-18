// EDGE CASE TEST FIXTURE — Helper file for split_across_files.js
// This file contains the eval portion of a malicious pattern
// The fetch is in split_across_files.js
// NOTE: Glassware scans per-file, so this may NOT be detected
// This is a KNOWN LIMITATION - cross-file flows are not tracked

const crypto = require('crypto');

// Hardcoded key for decryption
const DECRYPTION_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const DECRYPTION_IV = 'BBBBBBBBBBBBBBBB';

/**
 * Process encrypted payload received from fetch
 * This function is called with data fetched in split_across_files.js
 */
function processPayload(encryptedData) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', DECRYPTION_KEY, DECRYPTION_IV);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    // Execute the decrypted payload
    // NOTE: The fetch happened in a different file
    eval(decrypted);
}

module.exports = { processPayload };
