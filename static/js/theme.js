/**
 * Theme switcher functionality
 * Handles switching between light and dark modes with local storage persistence
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize theme from localStorage or default to dark
    const savedTheme = localStorage.getItem('theme') || 'dark';
    setTheme(savedTheme);
    
    // Add event listener to theme toggle button
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
});

/**
 * Toggle between light and dark themes
 */
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-bs-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
}

/**
 * Set the theme and save to localStorage
 * @param {string} theme - 'light' or 'dark'
 */
function setTheme(theme) {
    document.documentElement.setAttribute('data-bs-theme', theme);
    document.body.setAttribute('data-bs-theme', theme);
    localStorage.setItem('theme', theme);
    
    // Update theme toggle text based on current theme
    const themeToggleText = document.getElementById('theme-toggle-text');
    if (themeToggleText) {
        themeToggleText.textContent = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
    }
}