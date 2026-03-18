// SANITIZED TEST FIXTURE — reconstructed from public IOCs for detection testing
// Wave 1: PUA Unicode decoder pattern (Mar-May 2025)
// Source: Aikido "Delivering malware via Google Calendar invites and PUAs"
// Pattern: codePointAt + 0xFE00/0xE0100 ranges + Buffer.from + eval

const decodeUnicodePayload = (s) => {
    return [...s].map(c => {
        c = c.codePointAt(0);
        // Map Variation Selectors to byte values
        if (c >= 0xFE00 && c <= 0xFE0F) {
            return c - 0xFE00;
        }
        // Map Variation Selectors Supplement to byte values
        if (c >= 0xE0100 && c <= 0xE01EF) {
            return c - 0xE0100 + 16;
        }
        return null;
    }).filter(b => b !== null);
};

// High-entropy base64 placeholder (represents where invisible chars would be encoded)
// In real attack, this would contain Variation Selectors encoding the payload
const encodedPayload = `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;

// Decode and execute
eval(Buffer.from(decodeUnicodePayload(encodedPayload)).toString('utf-8'));
