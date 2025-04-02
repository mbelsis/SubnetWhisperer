/**
 * Subnet Whisperer - Main JavaScript
 * Common functions and utilities used across the application
 */

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
});

/**
 * Format a date string into a more readable format
 * @param {string} dateString - ISO date string
 * @param {boolean} includeTime - Whether to include time
 * @returns {string} Formatted date string
 */
function formatDate(dateString, includeTime = true) {
    if (!dateString) return '';
    
    const date = new Date(dateString);
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
    
    return date.toLocaleDateString(undefined, options);
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
    alert.className = `alert alert-${type}${dismissible ? ' alert-dismissible fade show' : ''}`;
    alert.role = 'alert';
    
    alert.innerHTML = message;
    
    if (dismissible) {
        alert.innerHTML += '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>';
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
        <div class="toast-header bg-${type} text-white">
            <strong class="me-auto">${title}</strong>
            <small>just now</small>
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
        <div class="toast-body">${message}</div>
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
