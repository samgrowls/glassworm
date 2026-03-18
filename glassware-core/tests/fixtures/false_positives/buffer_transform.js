// FALSE POSITIVE TEST FIXTURE — Legitimate buffer transformation
// This file should produce ZERO findings
// Pattern: Buffer manipulation for encoding conversion and binary protocol parsing
// NO eval, NO crypto API misuse, NO dynamic execution

/**
 * Convert a UTF-8 string to Latin1 encoding
 * Used for legacy system compatibility
 */
function utf8ToLatin1(str) {
    const buffer = Buffer.from(str, 'utf8');
    return buffer.toString('latin1');
}

/**
 * Convert a Latin1 string to UTF-8 encoding
 */
function latin1ToUtf8(str) {
    const buffer = Buffer.from(str, 'latin1');
    return buffer.toString('utf8');
}

/**
 * Parse a binary protocol message
 * Format: [length:2 bytes][type:1 byte][payload:length-1 bytes]
 */
function parseMessage(buffer) {
    if (buffer.length < 3) {
        throw new Error('Message too short');
    }
    
    // Read length (big-endian 16-bit)
    const length = buffer.readUInt16BE(0);
    
    // Read message type
    const messageType = buffer.readUInt8(2);
    
    // Read payload
    const payload = buffer.slice(3, length);
    
    return {
        length,
        messageType,
        payload,
        payloadHex: payload.toString('hex')
    };
}

/**
 * Create a binary protocol message
 */
function createMessage(messageType, payload) {
    const length = 3 + payload.length;
    const buffer = Buffer.alloc(length);
    
    // Write length
    buffer.writeUInt16BE(length, 0);
    
    // Write message type
    buffer.writeUInt8(messageType, 2);
    
    // Write payload
    payload.copy(buffer, 3);
    
    return buffer;
}

/**
 * Convert between ArrayBuffer and Buffer
 */
function arrayBufferToBuffer(arrayBuffer) {
    return Buffer.from(arrayBuffer);
}

function bufferToArrayBuffer(buffer) {
    return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}

// Example usage
const message = createMessage(0x01, Buffer.from('Hello, World!'));
console.log('Message:', message.toString('hex'));

const parsed = parseMessage(message);
console.log('Parsed:', parsed);

// Encoding conversion
const utf8String = 'Hello, 世界!';
const latin1 = utf8ToLatin1(utf8String);
const backToUtf8 = latin1ToUtf8(latin1);

module.exports = {
    utf8ToLatin1,
    latin1ToUtf8,
    parseMessage,
    createMessage,
    arrayBufferToBuffer,
    bufferToArrayBuffer
};
