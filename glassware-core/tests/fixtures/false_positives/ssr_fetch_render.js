// FALSE POSITIVE TEST FIXTURE — Server-side rendering fetch pattern
// This file should produce ZERO findings
// Pattern: SSR that fetches HTML from CMS and inserts via innerHTML
// NO eval, NO crypto, NO exec - this is a common legitimate pattern

/**
 * Server-side rendering helper that fetches content from a CMS
 * and renders it to the page
 */

const CMS_BASE_URL = 'https://cms.example.com';

/**
 * Fetch page content from CMS
 */
async function fetchPageContent(pageId) {
    const response = await fetch(`${CMS_BASE_URL}/pages/${pageId}`);
    if (!response.ok) {
        throw new Error(`Failed to fetch page: ${response.status}`);
    }
    const content = await response.text();
    return content;
}

/**
 * Render CMS content to the page
 * Uses innerHTML to insert trusted CMS content
 */
async function renderPage(pageId, containerId) {
    try {
        const content = await fetchPageContent(pageId);
        const container = document.getElementById(containerId);
        if (container) {
            // This is a common SSR pattern - inserting trusted CMS content
            // The CMS is a trusted source, not user-generated content
            container.innerHTML = content;
        }
    } catch (error) {
        console.error('Failed to render page:', error);
        const container = document.getElementById(containerId);
        if (container) {
            container.innerHTML = '<p>Failed to load content.</p>';
        }
    }
}

/**
 * Fetch and render multiple page sections
 */
async function renderPageSections(sections) {
    const promises = sections.map(({ pageId, containerId }) => {
        return renderPage(pageId, containerId);
    });
    await Promise.all(promises);
}

// Example usage: Render header, main content, and footer
renderPageSections([
    { pageId: 'header', containerId: 'header-container' },
    { pageId: 'main', containerId: 'main-content' },
    { pageId: 'footer', containerId: 'footer-container' }
]);

module.exports = { fetchPageContent, renderPage, renderPageSections };
