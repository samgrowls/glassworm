// FALSE POSITIVE TEST FIXTURE — Normal API client
// This file should produce ZERO findings
// Pattern: Standard REST API client that fetches JSON and renders to DOM
// NO eval, NO decrypt, NO exec, NO crypto

/**
 * API client for fetching and displaying user data
 * Uses standard fetch() pattern with JSON parsing
 */

const API_BASE_URL = 'https://api.example.com';

/**
 * Fetch users from the API
 */
async function fetchUsers() {
    const response = await fetch(`${API_BASE_URL}/users`);
    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    return data;
}

/**
 * Fetch a single user by ID
 */
async function fetchUser(userId) {
    const response = await fetch(`${API_BASE_URL}/users/${userId}`);
    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    return data;
}

/**
 * Create a new user
 */
async function createUser(userData) {
    const response = await fetch(`${API_BASE_URL}/users`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData)
    });
    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    return data;
}

/**
 * Render users to the DOM
 */
function renderUsers(users) {
    const container = document.getElementById('user-list');
    if (!container) return;
    
    container.innerHTML = users.map(user => `
        <div class="user-card">
            <h3>${escapeHtml(user.name)}</h3>
            <p>${escapeHtml(user.email)}</p>
        </div>
    `).join('');
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Initialize the user list
 */
async function init() {
    try {
        const users = await fetchUsers();
        renderUsers(users);
    } catch (error) {
        console.error('Failed to load users:', error);
    }
}

// Run on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

module.exports = { fetchUsers, fetchUser, createUser, renderUsers };
