// FALSE POSITIVE TEST FIXTURE — Legitimate XOR checksum
// This file should produce ZERO findings
// Pattern: Simple XOR checksum function for data integrity
// Has XOR loop but is clearly a checksum, NOT RC4
// NO 256-element array, NO swap, NO dynamic exec

/**
 * Calculate XOR checksum of a byte array
 * Used for simple data integrity verification
 */
function calculateXorChecksum(data) {
    let checksum = 0;
    for (let i = 0; i < data.length; i++) {
        checksum ^= data[i];
    }
    return checksum;
}

/**
 * Calculate XOR checksum of a string
 */
function calculateStringChecksum(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    return calculateXorChecksum(data);
}

/**
 * Verify data integrity using XOR checksum
 */
function verifyChecksum(data, expectedChecksum) {
    const calculated = calculateXorChecksum(data);
    return calculated === expectedChecksum;
}

/**
 * Packet class with checksum validation
 */
class Packet {
    constructor(payload) {
        this.payload = payload;
        this.checksum = calculateXorChecksum(payload);
    }
    
    isValid() {
        return this.checksum === calculateXorChecksum(this.payload);
    }
}

// Example usage
const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
const checksum = calculateXorChecksum(data);
console.log('Checksum:', checksum.toString(16));

const packet = new Packet(data);
console.log('Packet valid:', packet.isValid());

module.exports = { calculateXorChecksum, calculateStringChecksum, verifyChecksum, Packet };
