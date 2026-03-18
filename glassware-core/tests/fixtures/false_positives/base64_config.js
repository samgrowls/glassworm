// FALSE POSITIVE TEST FIXTURE — Legitimate high-entropy content
// This file should produce ZERO findings
// Pattern: Base64 strings used as configuration (JWT, API fixtures, test data)
// NO eval, NO Function constructor, NO dynamic execution

/**
 * Configuration file with base64-encoded test fixtures
 * These are used for unit testing API responses
 */

// JWT token fixture for testing (decoded payload is public test data)
const TEST_JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// API response fixture (base64 encoded for testing)
const API_RESPONSE_FIXTURE = "eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJ1c2VycyI6W3siaWQiOjEsIm5hbWUiOiJBbGljZSJ9LHsiaWQiOjIsIm5hbWUiOiJCb2IifV19LCJtZXNzYWdlIjoiRGF0YSByZXRyaWV2ZWQgc3VjY2Vzc2Z1bGx5In0=";

// Test data for encoding/decoding tests
const TEST_BASE64_DATA = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIHRoYXQgaXMgdXNlZCBmb3IgdW5pdCB0ZXN0aW5nIGJhc2U2NCBlbmNvZGluZyBhbmQgZGVjb2RpbmcgZnVuY3Rpb25hbGl0eS4=";

// Public key for JWT verification (shortened for brevity)
const JWT_PUBLIC_KEY = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF0NnFOaXpYb3VlRm1lYm93VXJqCnN5TWNJd3NkYU5vM3V6ZGxYQ1VQWnJxVnBqVGtGUHJFbG5GZUxqYU5lVnNkZkdsNmFzZGZhc2RmYXNkZmFzZGYKYXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZgphc2RmYXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmCmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZmFzZGYKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t";

/**
 * Decode base64 test fixture
 * Used for unit testing - no dynamic execution
 */
function decodeTestFixture(base64String) {
    return Buffer.from(base64String, 'base64').toString('utf8');
}

// Export test fixtures
module.exports = {
    TEST_JWT_TOKEN,
    API_RESPONSE_FIXTURE,
    TEST_BASE64_DATA,
    JWT_PUBLIC_KEY,
    decodeTestFixture
};
