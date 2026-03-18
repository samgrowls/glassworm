// FALSE POSITIVE TEST FIXTURE — SVG data URI
// This file should produce ZERO findings
// Pattern: Base64 SVG data URI for icons
// NO eval, NO Function constructor, NO dynamic execution, NO crypto

/**
 * Icon component using base64-encoded SVG data URI
 * Common pattern in React/Vue components for inline icons
 */

// Base64-encoded SVG icon (checkmark)
const checkmarkIcon = `data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9ImN1cnJlbnRDb2xvciIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxwb2x5bGluZSBwb2ludHM9IjIwIDYgOSAxNyA0IDEyIj48L3BvbHlsaW5lPjwvc3ZnPg==`;

// Base64-encoded SVG icon (X mark)
const closeIcon = `data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9ImN1cnJlbnRDb2xvciIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxsaW5lIHgxPSIxOCIgeTE9IjYiIHgyPSI2IiB5Mj0iMTgiPjwvbGluZT48bGluZSB4MT0iNiIgeTE9IjYiIHgyPSIxOCIgeTI9IjE4Ij48L2xpbmU+PC9zdmc+`;

// Base64-encoded SVG icon (warning)
const warningIcon = `data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9ImN1cnJlbnRDb2xvciIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxwYXRoIGQ9Ik0xMC4yOSAzLjg2TDEuODIgMThhMiAyIDAgMCAwIDEuNzEgM2gxOC45NGEyIDIgMCAwIDAgMS43MS0zTDEzLjcxIDMuODZhMiAyIDAgMCAwLTMuNDIgMHoiPjwvcGF0aD48bGluZSB4MT0iMTIiIHkxPSI5IiB4Mj0iMTIiIHkyPSIxMyI+PC9saW5lPjxsaW5lIHgxPSIxMiIgeTE9IjE3IiB4Mj0iMTIuMDEiIHkyPSIxNyI+PC9saW5lPjwvc3ZnPg==`;

/**
 * React-style icon component
 */
function Icon({ type = 'checkmark', size = 24 }) {
    const icons = {
        checkmark: checkmarkIcon,
        close: closeIcon,
        warning: warningIcon
    };
    
    return {
        type: 'img',
        src: icons[type] || checkmarkIcon,
        width: size,
        height: size
    };
}

// Example usage
const icon = Icon({ type: 'checkmark', size: 32 });
document.getElementById('icon').src = icon.src;

module.exports = { Icon, checkmarkIcon, closeIcon, warningIcon };
