document.addEventListener('DOMContentLoaded', function() {
    // Credential Sets toggle
    const useCredentialSetsCheckbox = document.getElementById('useCredentialSets');
    const credentialSetsSection = document.getElementById('credentialSetsSection');
    const manualCredentialsSection = document.getElementById('manualCredentialsSection');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const privateKeyInput = document.getElementById('privateKey');
    const credentialSetSelect = document.getElementById('credentialSet');
    
    if (useCredentialSetsCheckbox) {
        useCredentialSetsCheckbox.addEventListener('change', function() {
            if (this.checked) {
                credentialSetsSection.style.display = 'block';
                manualCredentialsSection.style.display = 'none';
                // Make credential set required and manual credentials not required
                credentialSetSelect.setAttribute('required', '');
                usernameInput.removeAttribute('required');
                passwordInput.removeAttribute('required');
                privateKeyInput.removeAttribute('required');
            } else {
                credentialSetsSection.style.display = 'none';
                manualCredentialsSection.style.display = 'block';
                // Make username required and credential set not required
                usernameInput.setAttribute('required', '');
                credentialSetSelect.removeAttribute('required');
                // Re-trigger auth type change to set appropriate required fields
                authTypeSelect.dispatchEvent(new Event('change'));
            }
        });
    }
    
    // Authentication type toggle
    const authTypeSelect = document.getElementById('authType');
    const passwordField = document.getElementById('passwordField');
    const privateKeyField = document.getElementById('privateKeyField');
    
    if (authTypeSelect) {
        authTypeSelect.addEventListener('change', function() {
            if (this.value === 'password') {
                passwordField.classList.remove('d-none');
                privateKeyField.classList.add('d-none');
                if (!useCredentialSetsCheckbox || !useCredentialSetsCheckbox.checked) {
                    passwordInput.setAttribute('required', '');
                    privateKeyInput.removeAttribute('required');
                }
            } else {
                passwordField.classList.add('d-none');
                privateKeyField.classList.remove('d-none');
                if (!useCredentialSetsCheckbox || !useCredentialSetsCheckbox.checked) {
                    passwordInput.removeAttribute('required');
                    privateKeyInput.setAttribute('required', '');
                }
            }
        });
        
        // Trigger change event on page load
        authTypeSelect.dispatchEvent(new Event('change'));
    }
    
    // Handle scan form submission
    const scanForm = document.getElementById('scanForm');
    const scanProgressModal = new bootstrap.Modal(document.getElementById('scanProgressModal'));
    const scanProgressBar = document.getElementById('scanProgressBar');
    const totalIPsElement = document.getElementById('totalIPs');
    const completedIPsElement = document.getElementById('completedIPs');
    const successIPsElement = document.getElementById('successIPs');
    const failedIPsElement = document.getElementById('failedIPs');
    
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Form validation
            if (!scanForm.checkValidity()) {
                e.stopPropagation();
                scanForm.classList.add('was-validated');
                return;
            }
            
            // Show progress modal
            scanProgressModal.show();
            
            // Collect form data
            const formData = new FormData(scanForm);
            
            // Include credential set data if using credential sets
            if (useCredentialSetsCheckbox && useCredentialSetsCheckbox.checked) {
                // Use credential set selection instead of manual credentials
                formData.delete('username');
                formData.delete('password');
                formData.delete('privateKey');
                formData.delete('authType');
                
                // Add credential set ID
                formData.append('use_credential_sets', true);
                
                // If multiple credentials checkbox is checked
                if (document.getElementById('multipleCredentials').checked) {
                    formData.append('multiple_credentials', true);
                }
            } else {
                formData.append('use_credential_sets', false);
                formData.append('multiple_credentials', false);
            }
            
            // Execute the scan
            fetch('/start_scan', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const scanId = data.scan_id;
                    pollScanStatus(scanId);
                } else {
                    alert('Error starting scan: ' + data.message);
                    scanProgressModal.hide();
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error starting scan. Please try again.');
                scanProgressModal.hide();
            });
        });
    }
    
    // Poll scan status
    function pollScanStatus(scanId) {
        fetch(`/scan_status/${scanId}`)
            .then(response => response.json())
            .then(data => {
                // Update progress UI
                const percentComplete = data.percent_complete;
                scanProgressBar.style.width = `${percentComplete}%`;
                scanProgressBar.setAttribute('aria-valuenow', percentComplete);
                
                totalIPsElement.textContent = data.total;
                completedIPsElement.textContent = data.completed;
                
                // If scan is complete, show results link
                if (data.status === 'completed' || percentComplete >= 100) {
                    document.getElementById('viewResultsBtn').classList.remove('d-none');
                    document.getElementById('viewResultsBtn').setAttribute('href', `/results?scan_id=${scanId}`);
                    return;
                }
                
                // Continue polling
                setTimeout(() => pollScanStatus(scanId), 2000);
            })
            .catch(error => {
                console.error('Error polling scan status:', error);
                // Continue polling even on error
                setTimeout(() => pollScanStatus(scanId), 2000);
            });
    }
    
    // Validate subnets button
    const validateSubnetsBtn = document.getElementById('validateSubnets');
    const subnetsTextarea = document.getElementById('subnets');
    const validationResultSpan = document.getElementById('validationResult');
    
    if (validateSubnetsBtn) {
        validateSubnetsBtn.addEventListener('click', function() {
            const subnets = subnetsTextarea.value.trim();
            
            if (!subnets) {
                validationResultSpan.innerHTML = '<span class="text-danger">Please enter subnets</span>';
                return;
            }
            
            validationResultSpan.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1"></i> Validating...</span>';
            
            fetch('/validate_subnets', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    subnets: subnets
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.valid) {
                    validationResultSpan.innerHTML = `<span class="text-success"><i class="fas fa-check-circle me-1"></i> Valid! Found ${data.ip_count} IP addresses</span>`;
                } else {
                    validationResultSpan.innerHTML = `<span class="text-danger"><i class="fas fa-exclamation-circle me-1"></i> ${data.message}</span>`;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                validationResultSpan.innerHTML = '<span class="text-danger"><i class="fas fa-exclamation-circle me-1"></i> Validation failed</span>';
            });
        });
    }
    
    // Reset form button
    const resetFormBtn = document.getElementById('resetForm');
    
    if (resetFormBtn) {
        resetFormBtn.addEventListener('click', function() {
            scanForm.reset();
            scanForm.classList.remove('was-validated');
            validationResultSpan.textContent = '';
            
            // Reset dropdowns and toggles
            if (authTypeSelect) {
                authTypeSelect.dispatchEvent(new Event('change'));
            }
            
            if (useCredentialSetsCheckbox) {
                useCredentialSetsCheckbox.checked = false;
                useCredentialSetsCheckbox.dispatchEvent(new Event('change'));
            }
        });
    }
});