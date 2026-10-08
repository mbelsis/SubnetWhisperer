// Initialize Bootstrap tooltips and popovers
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Render server-side UTC timestamps in the viewer's local time.
    // Usage: <span data-utc="{{ dt.isoformat() }}">{{ dt }}</span>
    document.querySelectorAll('[data-utc]').forEach(function(el) {
        const value = el.getAttribute('data-utc');
        if (value) {
            const includeTime = el.getAttribute('data-utc-time') !== 'false';
            const formatted = formatDate(value, includeTime);
            if (formatted) {
                el.textContent = formatted;
                el.setAttribute('title', value.endsWith('Z') ? value : value + ' UTC');
            }
        }
    });
});

/**
 * Escape a value for safe interpolation into HTML (text or quoted attribute).
 * Always use this (or textContent) for any data that originates from the
 * server, scanned hosts or users.
 * @param {*} value - Value to escape (null/undefined become '')
 * @returns {string} Escaped string
 */
function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/**
 * Restrict a Bootstrap contextual type (success, danger, ...) to known values
 * so it can safely be used inside a class attribute.
 * @param {string} type - Requested type
 * @returns {string} A safe Bootstrap type
 */
function safeBootstrapType(type) {
    const allowed = ['primary', 'secondary', 'success', 'danger', 'warning', 'info', 'light', 'dark'];
    return allowed.includes(type) ? type : 'info';
}

/**
 * Parse a timestamp coming from the server. All server timestamps are UTC;
 * naive values (no "Z" or offset) are treated as UTC as well.
 * @param {string} value - ISO-ish date string
 * @returns {Date|null} Date object or null if invalid
 */
function parseServerDate(value) {
    if (!value) return null;
    let str = String(value).trim();
    // "2026-10-08 12:00:00" -> "2026-10-08T12:00:00"
    if (/^\d{4}-\d{2}-\d{2} \d/.test(str)) {
        str = str.replace(' ', 'T');
    }
    // No timezone designator -> UTC
    if (/T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(str)) {
        str += 'Z';
    }
    const date = new Date(str);
    return isNaN(date.getTime()) ? null : date;
}

/**
 * Return the CSRF token from the <meta name="csrf-token"> tag.
 * @returns {string} CSRF token or ''
 */
function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

const SESSION_EXPIRED_MESSAGE = 'Your session expired, reload the page';

/**
 * fetch() wrapper for the app's JSON API.
 * - Adds the X-CSRFToken header to every state-changing request.
 * - JSON-encodes a plain-object `json` option.
 * - Detects expired CSRF tokens / sessions and shows a clear message.
 * Never rejects for HTTP errors; network errors still reject.
 * @param {string} url - Request URL
 * @param {object} options - fetch options, plus optional `json` body
 * @returns {Promise<{ok: boolean, status: number, data: object}>}
 */
function apiFetch(url, options = {}) {
    const opts = Object.assign({}, options);
    const method = (opts.method || 'GET').toUpperCase();
    opts.method = method;
    const headers = new Headers(opts.headers || {});
    headers.set('Accept', 'application/json');
    if (opts.json !== undefined) {
        headers.set('Content-Type', 'application/json');
        opts.body = JSON.stringify(opts.json);
        delete opts.json;
    }
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
        const token = getCsrfToken();
        if (token) headers.set('X-CSRFToken', token);
    }
    opts.headers = headers;
    opts.credentials = opts.credentials || 'same-origin';

    return fetch(url, opts).then(response => {
        return response.text().then(text => {
            let data = null;
            try {
                data = text ? JSON.parse(text) : {};
            } catch (e) {
                data = null;
            }

            // Expired / missing CSRF token
            if (response.status === 400 && /csrf/i.test(text || '')) {
                showToast(SESSION_EXPIRED_MESSAGE, 'Session expired', 'warning');
                return { ok: false, status: 400, data: { error: SESSION_EXPIRED_MESSAGE }, csrfExpired: true };
            }

            // Session expired: login_required redirected us to the login page
            if (response.redirected && /\/login/.test(response.url) && data === null) {
                showToast(SESSION_EXPIRED_MESSAGE, 'Session expired', 'warning');
                return { ok: false, status: 401, data: { error: SESSION_EXPIRED_MESSAGE }, csrfExpired: true };
            }

            if (data === null) {
                data = { error: response.ok ? 'Unexpected response from server' : `Request failed (HTTP ${response.status})` };
            }
            if (response.status === 403 && !data.error) {
                data.error = 'You are not allowed to perform this action';
            }
            return { ok: response.ok, status: response.status, data: data };
        });
    });
}

/**
 * Format a date string into a more readable format
 * @param {string} dateString - ISO date string
 * @param {boolean} includeTime - Whether to include time
 * @returns {string} Formatted date string
 */
function formatDate(dateString, includeTime = true) {
    if (!dateString) return '';
    
    const date = parseServerDate(dateString);
    if (!date) return String(dateString);
    const options = {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    };
    
    if (includeTime) {
        options.hour = '2-digit';
        options.minute = '2-digit';
        options.second = '2-digit';
    }
    
    return includeTime ? date.toLocaleString(undefined, options) : date.toLocaleDateString(undefined, options);
}

/**
 * Format a number as a file size (KB, MB, GB)
 * @param {number} bytes - Size in bytes
 * @returns {string} Formatted size string
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Format execution time in a human-readable format
 * @param {number} seconds - Time in seconds
 * @returns {string} Formatted time string
 */
function formatExecutionTime(seconds) {
    if (!seconds) return 'N/A';
    
    if (seconds < 0.1) {
        return Math.round(seconds * 1000) + 'ms';
    } else if (seconds < 60) {
        return seconds.toFixed(2) + 's';
    } else {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = (seconds % 60).toFixed(0);
        return minutes + 'm ' + remainingSeconds + 's';
    }
}

/**
 * Create a Bootstrap alert element
 * @param {string} message - Alert message
 * @param {string} type - Alert type (success, danger, warning, info)
 * @param {boolean} dismissible - Whether the alert should be dismissible
 * @returns {HTMLElement} Alert element
 */
function createAlert(message, type = 'info', dismissible = true) {
    const alert = document.createElement('div');
    alert.className = `alert alert-${safeBootstrapType(type)}${dismissible ? ' alert-dismissible fade show' : ''}`;
    alert.setAttribute('role', 'alert');
    
    // Message is always treated as plain text
    alert.textContent = message === null || message === undefined ? '' : String(message);
    
    if (dismissible) {
        const closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'btn-close';
        closeBtn.setAttribute('data-bs-dismiss', 'alert');
        closeBtn.setAttribute('aria-label', 'Close');
        alert.appendChild(closeBtn);
    }
    
    return alert;
}

/**
 * Show a toast notification
 * @param {string} message - Toast message
 * @param {string} title - Toast title
 * @param {string} type - Toast type (success, danger, warning, info)
 */
function showToast(message, title = 'Notification', type = 'info') {
    // Create toast container if it doesn't exist
    let toastContainer = document.querySelector('.toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }
    
    // Create toast element
    const toastEl = document.createElement('div');
    toastEl.className = 'toast';
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');
    
    // Set toast content
    toastEl.innerHTML = `
        <div class="toast-header bg-${safeBootstrapType(type)} text-white">
            <strong class="me-auto">${escapeHtml(title)}</strong>
            <small>just now</small>
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
        <div class="toast-body">${escapeHtml(message)}</div>
    `;
    
    // Add toast to container
    toastContainer.appendChild(toastEl);
    
    // Initialize and show toast
    const toast = new bootstrap.Toast(toastEl, {
        autohide: true,
        delay: 5000
    });
    toast.show();
    
    // Remove toast element after it's hidden
    toastEl.addEventListener('hidden.bs.toast', function() {
        toastEl.remove();
    });
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 * @returns {Promise} Promise that resolves when text is copied
 */
function copyToClipboard(text) {
    if (navigator.clipboard) {
        return navigator.clipboard.writeText(text)
            .then(() => {
                showToast('Copied to clipboard!', 'Success', 'success');
                return true;
            })
            .catch(err => {
                console.error('Failed to copy text: ', err);
                return false;
            });
    } else {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            const successful = document.execCommand('copy');
            const message = successful ? 'Copied to clipboard!' : 'Failed to copy text';
            const type = successful ? 'success' : 'danger';
            showToast(message, successful ? 'Success' : 'Error', type);
            return Promise.resolve(successful);
        } catch (err) {
            console.error('Failed to copy text: ', err);
            return Promise.resolve(false);
        } finally {
            document.body.removeChild(textArea);
        }
    }
}

/**
 * Download data as a file
 * @param {string} filename - Name of the file to download
 * @param {string} content - Content of the file
 * @param {string} contentType - MIME type of the file
 */
function downloadFile(filename, content, contentType = 'text/plain') {
    const element = document.createElement('a');
    const file = new Blob([content], {type: contentType});
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
}

/**
 * Convert object to CSV format
 * @param {Array} array - Array of objects to convert
 * @returns {string} CSV string
 */
function convertToCSV(array) {
    if (array.length === 0) return '';
    
    const keys = Object.keys(array[0]);
    const csvHeader = keys.join(',') + '\n';
    
    const csvRows = array.map(obj => {
        return keys.map(key => {
            let value = obj[key];
            
            // Handle complex objects by stringifying
            if (typeof value === 'object' && value !== null) {
                value = JSON.stringify(value).replace(/"/g, '""');
            }
            
            // Escape quotes and wrap in quotes if necessary
            if (value === null || value === undefined) {
                return '';
            } else if (typeof value === 'string') {
                value = value.replace(/"/g, '""');
                return `"${value}"`;
            } else {
                return value;
            }
        }).join(',');
    }).join('\n');
    
    return csvHeader + csvRows;
}

/**
 * Generate a color scale for charts
 * @param {number} count - Number of colors to generate
 * @param {string} scheme - Color scheme name
 * @returns {Array} Array of color strings
 */
function generateColorScale(count, scheme = 'default') {
    const schemes = {
        default: ['#0d6efd', '#6610f2', '#6f42c1', '#d63384', '#dc3545', '#fd7e14', '#ffc107', '#198754', '#20c997', '#0dcaf0'],
        pastel: ['#B5EAD7', '#C7CEEA', '#E2F0CB', '#FFDAC1', '#FFB7B2', '#FF9AA2', '#F2E2D2', '#BFD8D5', '#B8F2E6', '#D4F0F0'],
        vibrant: ['#FF6B6B', '#4ECDC4', '#45B7D1', '#F9DB6D', '#FE9920', '#E84855', '#403F4C', '#2E86AB', '#A23B72', '#37505C'],
        monochrome: ['#000000', '#212529', '#343a40', '#495057', '#6c757d', '#adb5bd', '#ced4da', '#dee2e6', '#e9ecef', '#f8f9fa']
    };
    
    const colors = schemes[scheme] || schemes.default;
    
    if (count <= colors.length) {
        return colors.slice(0, count);
    } else {
        // If we need more colors than available, cycle through the colors
        const result = [];
        for (let i = 0; i < count; i++) {
            result.push(colors[i % colors.length]);
        }
        return result;
    }
}

/**
 * Validate an IP address
 * @param {string} ip - IP address to validate
 * @returns {boolean} Whether the IP address is valid
 */
function isValidIpAddress(ip) {
    // Regular expression for IPv4 address
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(ip);
}

/**
 * Validate a subnet in CIDR notation
 * @param {string} subnet - Subnet to validate
 * @returns {boolean} Whether the subnet is valid
 */
function isValidSubnet(subnet) {
    // Regular expression for IPv4 CIDR notation
    const cidrRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(3[0-2]|[1-2][0-9]|[0-9])$/;
    return cidrRegex.test(subnet);
}

/**
 * Validate an IP range
 * @param {string} range - IP range to validate
 * @returns {boolean} Whether the IP range is valid
 */
function isValidIpRange(range) {
    // Check if range contains a hyphen
    if (!range.includes('-')) return false;
    
    const parts = range.split('-');
    if (parts.length !== 2) return false;
    
    const start = parts[0].trim();
    let end = parts[1].trim();
    
    // If end is just a number, assume it's the last octet
    if (/^\d+$/.test(end) && !end.includes('.')) {
        const startParts = start.split('.');
        if (startParts.length !== 4) return false;
        
        end = `${startParts[0]}.${startParts[1]}.${startParts[2]}.${end}`;
    }
    
    // Validate both start and end as IP addresses
    return isValidIpAddress(start) && isValidIpAddress(end);
}
