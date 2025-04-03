/**
 * JavaScript for handling credential display logic in the scan form
 */
document.addEventListener('DOMContentLoaded', function() {
    // Elements
    const useCredentialSetsCheckbox = document.getElementById('use_credential_sets');
    const multipleCredentialsCheckbox = document.getElementById('multiple_credentials');
    const manualCredentialsSection = document.getElementById('manual_credentials_section');
    const credentialSetSection = document.getElementById('credential_set_section');
    const credentialSetSelect = document.getElementById('credential_set');
    
    // Form submit handler
    const form = document.getElementById('scan_form');
    
    // Initialize visibility based on initial checkbox state
    toggleCredentialSections();
    
    // Event listeners
    if (useCredentialSetsCheckbox) {
        useCredentialSetsCheckbox.addEventListener('change', toggleCredentialSections);
    }
    
    if (multipleCredentialsCheckbox) {
        multipleCredentialsCheckbox.addEventListener('change', toggleCredentialSetDropdown);
    }
    
    // Toggle credential sections based on checkbox
    function toggleCredentialSections() {
        if (useCredentialSetsCheckbox && manualCredentialsSection && credentialSetSection) {
            if (useCredentialSetsCheckbox.checked) {
                manualCredentialsSection.classList.add('d-none');
                credentialSetSection.classList.remove('d-none');
                // Update multiple credentials checkbox visibility
                toggleCredentialSetDropdown();
            } else {
                manualCredentialsSection.classList.remove('d-none');
                credentialSetSection.classList.add('d-none');
            }
        }
    }
    
    // Toggle credential set dropdown based on multiple credentials checkbox
    function toggleCredentialSetDropdown() {
        if (multipleCredentialsCheckbox && credentialSetSelect) {
            // If using multiple credentials, hide the credential set dropdown
            if (multipleCredentialsCheckbox.checked) {
                document.getElementById('credential_set_dropdown').classList.add('d-none');
                document.getElementById('multiple_credentials_info').classList.remove('d-none');
            } else {
                document.getElementById('credential_set_dropdown').classList.remove('d-none');
                document.getElementById('multiple_credentials_info').classList.add('d-none');
            }
        }
    }
    
    // Form submission handling
    if (form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Validate form
            if (!validateForm()) {
                return false;
            }
            
            // Collect form data
            const formData = new FormData(form);
            const jsonData = {};
            
            // Convert FormData to JSON
            for (const [key, value] of formData.entries()) {
                jsonData[key] = value;
            }
            
            // Add credential set flags
            if (useCredentialSetsCheckbox) {
                jsonData.use_credential_sets = useCredentialSetsCheckbox.checked;
                jsonData.multiple_credentials = multipleCredentialsCheckbox ? multipleCredentialsCheckbox.checked : false;
            }
            
            // Start the scan
            startScan(jsonData);
        });
    }
    
    // Validate the form before submission
    function validateForm() {
        // Validate subnets
        const subnets = document.getElementById('subnets').value.trim();
        if (!subnets) {
            showError('Please enter at least one subnet.');
            return false;
        }
        
        // Validate credentials based on mode
        if (useCredentialSetsCheckbox && useCredentialSetsCheckbox.checked) {
            // Using credential sets
            if (!multipleCredentialsCheckbox.checked && 
                (!credentialSetSelect.value || credentialSetSelect.value === '0')) {
                showError('Please select a credential set or use multiple credentials option.');
                return false;
            }
        } else {
            // Manual credentials
            const username = document.getElementById('username').value.trim();
            const authType = document.querySelector('input[name="authType"]:checked').value;
            
            if (!username) {
                showError('Username is required.');
                return false;
            }
            
            if (authType === 'password') {
                const password = document.getElementById('password').value;
                if (!password) {
                    showError('Password is required when using password authentication.');
                    return false;
                }
            } else if (authType === 'key') {
                const privateKey = document.getElementById('privateKey').value.trim();
                if (!privateKey) {
                    showError('Private key is required when using key authentication.');
                    return false;
                }
            }
        }
        
        return true;
    }
    
    // Display error message
    function showError(message) {
        const alertEl = document.createElement('div');
        alertEl.className = 'alert alert-danger alert-dismissible fade show';
        alertEl.role = 'alert';
        alertEl.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Add to page
        const container = document.querySelector('.container');
        container.insertBefore(alertEl, container.firstChild);
        
        // Scroll to top
        window.scrollTo(0, 0);
    }
});