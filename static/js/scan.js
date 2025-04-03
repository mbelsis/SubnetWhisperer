/**
 * Subnet Whisperer - Scan Page JavaScript
 * Functionality for the subnet scanning page
 */

document.addEventListener('DOMContentLoaded', function() {
    // Elements
    const scanForm = document.getElementById('scanForm');
    const csvImportForm = document.getElementById('csvImportForm');
    const authTypeSelect = document.getElementById('authType');
    const passwordField = document.getElementById('passwordField');
    const privateKeyField = document.getElementById('privateKeyField');
    const validateSubnetsBtn = document.getElementById('validateSubnets');
    const subnetsInput = document.getElementById('subnets');
    const resetFormBtn = document.getElementById('resetForm');
    const commandTemplateSelect = document.getElementById('commandTemplate');
    const customCommandsTextarea = document.getElementById('customCommands');
    
    // Progress modal elements
    const scanProgressModal = document.getElementById('scanProgressModal');
    const scanProgressBar = document.getElementById('scanProgressBar');
    const totalIPsElement = document.getElementById('totalIPs');
    const completedIPsElement = document.getElementById('completedIPs');
    const remainingIPsElement = document.getElementById('remainingIPs');
    const scanActivityElement = document.getElementById('scanActivity');
    const cancelScanBtn = document.getElementById('cancelScan');
    const viewResultsBtn = document.getElementById('viewResults');
    
    let scanInterval; // For tracking the interval that checks scan progress
    let currentScanId; // To track the current scan ID
    let isScanRunning = false;
    
    // Toggle between password and key authentication
    authTypeSelect.addEventListener('change', function() {
        if (this.value === 'password') {
            passwordField.classList.remove('d-none');
            privateKeyField.classList.add('d-none');
            document.getElementById('password').setAttribute('required', 'required');
            document.getElementById('privateKey').removeAttribute('required');
        } else {
            passwordField.classList.add('d-none');
            privateKeyField.classList.remove('d-none');
            document.getElementById('password').removeAttribute('required');
            document.getElementById('privateKey').setAttribute('required', 'required');
        }
    });
    
    // Toggle detailed server info availability based on basic server info checkbox
    const collectServerInfoCheckbox = document.getElementById('collectServerInfo');
    const collectDetailedInfoCheckbox = document.getElementById('collectDetailedInfo');
    
    // Initialize detailed info checkbox state
    collectDetailedInfoCheckbox.disabled = !collectServerInfoCheckbox.checked;
    
    collectServerInfoCheckbox.addEventListener('change', function() {
        collectDetailedInfoCheckbox.disabled = !this.checked;
        if (!this.checked) {
            collectDetailedInfoCheckbox.checked = false;
        }
    });
    
    // Handle command template selection
    commandTemplateSelect.addEventListener('change', function() {
        if (this.value) {
            // Fetch template commands
            fetch(`/template/${this.value}`)
                .then(response => response.json())
                .then(data => {
                    // If there's already content in the custom commands, confirm before overwriting
                    if (customCommandsTextarea.value.trim() !== '') {
                        if (confirm('This will overwrite your custom commands. Continue?')) {
                            customCommandsTextarea.value = data.commands;
                        } else {
                            // Reset template selection if user cancels
                            this.value = '';
                        }
                    } else {
                        customCommandsTextarea.value = data.commands;
                    }
                })
                .catch(error => {
                    console.error('Error fetching template:', error);
                    showToast('Failed to load template', 'Error', 'danger');
                });
        }
    });
    
    // Validate subnets
    validateSubnetsBtn.addEventListener('click', function() {
        const subnetsText = subnetsInput.value.trim();
        if (!subnetsText) {
            document.getElementById('validationResult').innerHTML = '<span class="text-danger">Please enter at least one subnet or IP address</span>';
            return;
        }
        
        const validationResult = validateSubnets(subnetsText);
        document.getElementById('validationResult').innerHTML = validationResult.message;
    });
    
    // Reset form
    resetFormBtn.addEventListener('click', function() {
        if (confirm('Are you sure you want to reset the form? All entered data will be lost.')) {
            scanForm.reset();
            // Reset validation messages
            document.getElementById('validationResult').innerHTML = '';
        }
    });
    
    // Validate form before submission
    scanForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Validate subnets
        const subnetsText = subnetsInput.value.trim();
        if (!subnetsText) {
            showToast('Please enter at least one subnet or IP address', 'Validation Error', 'danger');
            return;
        }
        
        // Validate authentication
        const authType = authTypeSelect.value;
        if (authType === 'password' && !document.getElementById('password').value) {
            showToast('Please enter a password', 'Validation Error', 'danger');
            return;
        } else if (authType === 'key' && !document.getElementById('privateKey').value) {
            showToast('Please enter a private key', 'Validation Error', 'danger');
            return;
        }
        
        // Validate username
        if (!document.getElementById('username').value) {
            showToast('Please enter a username', 'Validation Error', 'danger');
            return;
        }
        
        // Validate that either template is selected or custom commands are provided
        if (!commandTemplateSelect.value && !customCommandsTextarea.value.trim()) {
            showToast('Please select a command template or enter custom commands', 'Validation Error', 'danger');
            return;
        }
        
        // Prepare data for API call
        const formData = {
            subnets: subnetsText,
            username: document.getElementById('username').value,
            auth_type: authType,
            password: authType === 'password' ? document.getElementById('password').value : '',
            private_key: authType === 'key' ? document.getElementById('privateKey').value : '',
            template_id: commandTemplateSelect.value || null,
            custom_commands: customCommandsTextarea.value.trim(),
            collect_server_info: document.getElementById('collectServerInfo').checked,
            collect_detailed_info: document.getElementById('collectDetailedInfo').checked,
            concurrency: document.getElementById('concurrency').value
        };
        
        // Show the scan progress modal
        const scanProgressModalEl = new bootstrap.Modal(scanProgressModal);
        scanProgressModalEl.show();
        
        // Reset progress indicators
        scanProgressBar.style.width = '0%';
        scanProgressBar.setAttribute('aria-valuenow', '0');
        scanActivityElement.innerHTML = '<div class="text-muted">Preparing scan...</div>';
        
        // Start the scan
        startScan(formData);
    });
    
    // CSV Import Form
    csvImportForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const csvFile = document.getElementById('csvFile').files[0];
        if (!csvFile) {
            showToast('Please select a CSV file', 'Validation Error', 'danger');
            return;
        }
        
        const reader = new FileReader();
        reader.onload = function(event) {
            const csvContent = event.target.result;
            
            // Make an API call to parse the CSV and get the IP addresses
            fetch('/api/parse_csv', {
                method: 'POST',
                headers: {
                    'Content-Type': 'text/plain'
                },
                body: csvContent
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showToast(data.error, 'Error', 'danger');
                } else if (data.ip_addresses && data.ip_addresses.length > 0) {
                    // Populate the subnets textarea with the parsed IP addresses
                    subnetsInput.value = data.ip_addresses.join('\n');
                    
                    // Switch to the manual input tab
                    const manualTab = document.getElementById('manual-tab');
                    bootstrap.Tab.getOrCreateInstance(manualTab).show();
                    
                    showToast(`Imported ${data.ip_addresses.length} IP addresses from CSV`, 'Success', 'success');
                } else {
                    showToast('No valid IP addresses found in the CSV file', 'Warning', 'warning');
                }
            })
            .catch(error => {
                console.error('Error parsing CSV:', error);
                showToast('Failed to parse CSV file', 'Error', 'danger');
            });
        };
        
        reader.readAsText(csvFile);
    });
    
    // Cancel scan button
    cancelScanBtn.addEventListener('click', function() {
        if (confirm('Are you sure you want to cancel the scan?')) {
            stopScanProgress();
            // Make an API call to cancel the scan
            if (currentScanId) {
                fetch(`/api/cancel_scan/${currentScanId}`, { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        showToast('Scan cancelled', 'Info', 'info');
                    })
                    .catch(error => {
                        console.error('Error cancelling scan:', error);
                    });
            }
            
            // Hide the modal
            bootstrap.Modal.getInstance(scanProgressModal).hide();
        }
    });
    
    // View results button
    viewResultsBtn.addEventListener('click', function() {
        stopScanProgress();
        // Hide the modal
        bootstrap.Modal.getInstance(scanProgressModal).hide();
    });
    
    // Helper function to validate subnets
    function validateSubnets(subnetsText) {
        const lines = subnetsText.split(/[\n,]+/);
        let validCount = 0;
        let invalidSubnets = [];
        let totalIPs = 0;
        
        for (const line of lines) {
            const subnet = line.trim();
            if (!subnet) continue;
            
            if (isValidSubnet(subnet)) {
                validCount++;
                // Estimate number of IPs in subnet
                const cidrParts = subnet.split('/');
                const prefix = parseInt(cidrParts[1]);
                const numIPs = Math.pow(2, 32 - prefix) - 2; // Subtract network and broadcast addresses
                totalIPs += numIPs > 0 ? numIPs : 1;
            } else if (isValidIpRange(subnet)) {
                validCount++;
                // Estimate number of IPs in range
                const rangeParts = subnet.split('-');
                if (rangeParts.length === 2) {
                    const start = rangeParts[0].trim();
                    let end = rangeParts[1].trim();
                    
                    if (!end.includes('.')) {
                        // If end is just the last octet
                        const startParts = start.split('.');
                        const startLastOctet = parseInt(startParts[3]);
                        const endLastOctet = parseInt(end);
                        totalIPs += endLastOctet - startLastOctet + 1;
                    } else {
                        // Full IP addresses for start and end
                        const startIP = start.split('.').map(Number);
                        const endIP = end.split('.').map(Number);
                        // Simplified calculation for small ranges
                        const startNum = startIP[0] * 16777216 + startIP[1] * 65536 + startIP[2] * 256 + startIP[3];
                        const endNum = endIP[0] * 16777216 + endIP[1] * 65536 + endIP[2] * 256 + endIP[3];
                        totalIPs += endNum - startNum + 1;
                    }
                }
            } else if (isValidIpAddress(subnet)) {
                validCount++;
                totalIPs += 1;
            } else {
                invalidSubnets.push(subnet);
            }
        }
        
        if (invalidSubnets.length === 0) {
            return {
                valid: true,
                message: `<span class="text-success">✓ All ${validCount} subnets are valid. Approximately ${totalIPs} IP addresses.</span>`,
                count: validCount,
                totalIPs: totalIPs
            };
        } else {
            return {
                valid: false,
                message: `<span class="text-warning">⚠ ${invalidSubnets.length} invalid subnets found: ${invalidSubnets.join(', ')}</span>`,
                count: validCount,
                totalIPs: totalIPs,
                invalidSubnets: invalidSubnets
            };
        }
    }
    
    // Start a scan
    function startScan(formData) {
        // Reset scan state
        isScanRunning = true;
        
        // Make the API call to start the scan
        fetch('/start_scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showToast(data.error, 'Error', 'danger');
                bootstrap.Modal.getInstance(scanProgressModal).hide();
                return;
            }
            
            // Store the scan ID
            currentScanId = data.scan_id;
            
            // Add a log message
            addScanLogMessage(`Scan started for ${data.message}`);
            
            // Show the view results button with the correct link
            viewResultsBtn.href = `/results?scan_id=${currentScanId}`;
            
            // Start checking for progress
            startScanProgress();
        })
        .catch(error => {
            console.error('Error starting scan:', error);
            showToast('Failed to start scan', 'Error', 'danger');
            bootstrap.Modal.getInstance(scanProgressModal).hide();
        });
    }
    
    // Start checking scan progress
    function startScanProgress() {
        if (scanInterval) {
            clearInterval(scanInterval);
        }
        
        // Check progress every 2 seconds
        scanInterval = setInterval(() => {
            if (!currentScanId || !isScanRunning) {
                stopScanProgress();
                return;
            }
            
            fetch(`/scan_status/${currentScanId}`)
                .then(response => response.json())
                .then(data => {
                    // Update progress bar
                    const percentComplete = data.percent_complete;
                    scanProgressBar.style.width = `${percentComplete}%`;
                    scanProgressBar.setAttribute('aria-valuenow', percentComplete);
                    
                    // Update counts
                    totalIPsElement.textContent = data.total;
                    completedIPsElement.textContent = data.completed;
                    remainingIPsElement.textContent = data.total - data.completed;
                    
                    // Add log message if status changed
                    if (data.status === 'completed') {
                        addScanLogMessage('Scan completed successfully!');
                        scanCompleted();
                    } else if (data.status === 'failed') {
                        addScanLogMessage('Scan failed.');
                        scanCompleted();
                    }
                    
                    // Add log messages for newly completed hosts
                    if (data.recent_results) {
                        for (const result of data.recent_results) {
                            const status = result.status_code === 'success' ? 'succeeded' : 'failed';
                            addScanLogMessage(`${result.ip_address}: SSH connection ${status}`);
                        }
                    }
                })
                .catch(error => {
                    console.error('Error checking scan progress:', error);
                    // Don't stop on errors, keep trying
                });
        }, 2000);
    }
    
    // Stop checking scan progress
    function stopScanProgress() {
        if (scanInterval) {
            clearInterval(scanInterval);
            scanInterval = null;
        }
        isScanRunning = false;
    }
    
    // Scan completed
    function scanCompleted() {
        stopScanProgress();
        
        // Show 100% completion
        scanProgressBar.style.width = '100%';
        scanProgressBar.setAttribute('aria-valuenow', '100');
        
        // Change the color based on success/failure
        scanProgressBar.classList.remove('bg-primary');
        scanProgressBar.classList.add('bg-success');
        
        // Show the view results button
        viewResultsBtn.classList.remove('d-none');
        cancelScanBtn.textContent = 'Close';
        
        // Add a final log message
        addScanLogMessage('Scan completed. View results for detailed information.');
    }
    
    // Add a message to the scan log
    function addScanLogMessage(message) {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        logEntry.innerHTML = `<span class="text-secondary">[${timestamp}]</span> ${message}`;
        
        // Add to the top of the log
        scanActivityElement.insertBefore(logEntry, scanActivityElement.firstChild);
    }
});

// Function to simulate handling a CSV file for UI testing
// This would be replaced by a real API call in production
function handleCsvImport(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = function(event) {
            try {
                const lines = event.target.result.split('\n');
                let ipAddresses = [];
                
                for (const line of lines) {
                    const parts = line.split(',');
                    // Look for anything that might be an IP or subnet
                    for (const part of parts) {
                        const trimmed = part.trim();
                        if (isValidIpAddress(trimmed) || isValidSubnet(trimmed) || isValidIpRange(trimmed)) {
                            ipAddresses.push(trimmed);
                        }
                    }
                }
                
                resolve({
                    success: true,
                    ipAddresses: ipAddresses
                });
            } catch (error) {
                reject({
                    success: false,
                    error: 'Failed to parse CSV file'
                });
            }
        };
        
        reader.onerror = function() {
            reject({
                success: false,
                error: 'Failed to read CSV file'
            });
        };
        
        reader.readAsText(file);
    });
}
