/**
 * Subnet Whisperer - Scan page
 * Single authoritative script for #scan_form: credential toggles, subnet
 * validation, CSV import, starting the scan and polling its progress.
 *
 * Requires main.js (escapeHtml, apiFetch, createAlert).
 */
document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('scan_form');
    if (!form) return;

    // Credential set controls (only rendered for admins)
    const useCredentialSetsCheckbox = document.getElementById('use_credential_sets');
    const multipleCredentialsCheckbox = document.getElementById('multiple_credentials');
    const credentialSetSection = document.getElementById('credential_set_section');
    const credentialSetDropdown = document.getElementById('credential_set_dropdown');
    const multipleCredentialsInfo = document.getElementById('multiple_credentials_info');
    const credentialSetSelect = document.getElementById('credential_set');

    // Manual credential controls
    const manualCredentialsSection = document.getElementById('manual_credentials_section');
    const usernameInput = document.getElementById('username');
    const authTypeSelect = document.getElementById('authType');
    const passwordField = document.getElementById('passwordField');
    const passwordInput = document.getElementById('password');
    const privateKeyField = document.getElementById('privateKeyField');
    const privateKeyInput = document.getElementById('privateKey');
    const sudoPasswordInput = document.getElementById('sudoPassword');

    // Scan options
    const subnetsTextarea = document.getElementById('subnets');
    const templateSelect = document.getElementById('commandTemplate');
    const customCommandsTextarea = document.getElementById('customCommands');
    const collectServerInfoCheckbox = document.getElementById('collectServerInfo');
    const collectDetailedInfoCheckbox = document.getElementById('collectDetailedInfo');
    const concurrencyInput = document.getElementById('concurrency');
    const portInput = document.getElementById('port');
    const submitButton = form.querySelector('button[type="submit"]');

    // Feedback areas
    const formAlerts = document.getElementById('scanFormAlerts');
    const validateSubnetsBtn = document.getElementById('validateSubnets');
    const validationResult = document.getElementById('validationResult');

    // Progress modal
    const scanProgressModalEl = document.getElementById('scanProgressModal');
    const scanProgressModal = scanProgressModalEl ? new bootstrap.Modal(scanProgressModalEl) : null;
    const scanProgressTitle = document.getElementById('scanProgressModalLabel');
    const scanProgressBar = document.getElementById('scanProgressBar');
    const totalIPsElement = document.getElementById('totalIPs');
    const completedIPsElement = document.getElementById('completedIPs');
    const remainingIPsElement = document.getElementById('remainingIPs');
    const scanActivity = document.getElementById('scanActivity');
    const hideProgressBtn = document.getElementById('cancelScan');
    const viewResultsLink = document.getElementById('viewResults');

    let pollTimer = null;
    let pollFailures = 0;

    // ------------------------------------------------------------------
    // UI toggles
    // ------------------------------------------------------------------
    function usingCredentialSets() {
        return !!(useCredentialSetsCheckbox && useCredentialSetsCheckbox.checked);
    }

    function toggleCredentialSections() {
        if (!manualCredentialsSection) return;
        if (usingCredentialSets()) {
            manualCredentialsSection.classList.add('d-none');
            if (credentialSetSection) credentialSetSection.classList.remove('d-none');
        } else {
            manualCredentialsSection.classList.remove('d-none');
            if (credentialSetSection) credentialSetSection.classList.add('d-none');
        }
        toggleCredentialSetDropdown();
    }

    function toggleCredentialSetDropdown() {
        if (!multipleCredentialsCheckbox || !credentialSetDropdown || !multipleCredentialsInfo) return;
        if (multipleCredentialsCheckbox.checked) {
            credentialSetDropdown.classList.add('d-none');
            multipleCredentialsInfo.classList.remove('d-none');
        } else {
            credentialSetDropdown.classList.remove('d-none');
            multipleCredentialsInfo.classList.add('d-none');
        }
    }

    function toggleAuthFields() {
        if (!authTypeSelect) return;
        if (authTypeSelect.value === 'key') {
            passwordField.classList.add('d-none');
            privateKeyField.classList.remove('d-none');
        } else {
            passwordField.classList.remove('d-none');
            privateKeyField.classList.add('d-none');
        }
    }

    if (useCredentialSetsCheckbox) {
        useCredentialSetsCheckbox.addEventListener('change', toggleCredentialSections);
    }
    if (multipleCredentialsCheckbox) {
        multipleCredentialsCheckbox.addEventListener('change', toggleCredentialSetDropdown);
    }
    if (authTypeSelect) {
        authTypeSelect.addEventListener('change', toggleAuthFields);
    }
    toggleCredentialSections();
    toggleAuthFields();

    // ------------------------------------------------------------------
    // Messages
    // ------------------------------------------------------------------
    function clearMessages() {
        if (formAlerts) formAlerts.innerHTML = '';
    }

    function showMessage(message, type) {
        const alertEl = createAlert(message, type || 'danger', true);
        if (formAlerts) {
            formAlerts.innerHTML = '';
            formAlerts.appendChild(alertEl);
            formAlerts.scrollIntoView({ behavior: 'smooth', block: 'center' });
        } else {
            form.prepend(alertEl);
        }
    }

    // ------------------------------------------------------------------
    // Validation and payload
    // ------------------------------------------------------------------
    function validateForm() {
        if (!subnetsTextarea.value.trim()) {
            showMessage('Please enter at least one subnet or IP address.');
            return false;
        }

        if (usingCredentialSets()) {
            const multiple = multipleCredentialsCheckbox && multipleCredentialsCheckbox.checked;
            if (!multiple && (!credentialSetSelect || !credentialSetSelect.value || credentialSetSelect.value === '0')) {
                showMessage('Please select a credential set or enable "Try multiple credential sets".');
                return false;
            }
        } else {
            if (!usernameInput.value.trim()) {
                showMessage('Username is required.');
                return false;
            }
            const authType = authTypeSelect ? authTypeSelect.value : 'password';
            if (authType === 'password' && !passwordInput.value) {
                showMessage('Password is required when using password authentication.');
                return false;
            }
            if (authType === 'key' && !privateKeyInput.value.trim()) {
                showMessage('Private key is required when using key authentication.');
                return false;
            }
        }

        const port = parseInt(portInput ? portInput.value : '22', 10);
        if (isNaN(port) || port < 1 || port > 65535) {
            showMessage('Port must be a number between 1 and 65535.');
            return false;
        }

        const concurrency = parseInt(concurrencyInput.value, 10);
        if (isNaN(concurrency) || concurrency < 1) {
            showMessage('Concurrency must be at least 1.');
            return false;
        }

        return true;
    }

    function buildPayload() {
        const templateValue = templateSelect ? templateSelect.value : '';
        const payload = {
            subnets: subnetsTextarea.value.trim(),
            template_id: templateValue ? parseInt(templateValue, 10) : '',
            custom_commands: customCommandsTextarea ? customCommandsTextarea.value : '',
            collect_server_info: !!(collectServerInfoCheckbox && collectServerInfoCheckbox.checked),
            collect_detailed_info: !!(collectDetailedInfoCheckbox && collectDetailedInfoCheckbox.checked),
            concurrency: parseInt(concurrencyInput.value, 10) || 10,
            port: parseInt(portInput ? portInput.value : '22', 10) || 22,
            use_credential_sets: usingCredentialSets(),
            multiple_credentials: usingCredentialSets() && !!(multipleCredentialsCheckbox && multipleCredentialsCheckbox.checked)
        };

        if (payload.use_credential_sets) {
            if (!payload.multiple_credentials && credentialSetSelect) {
                payload.credential_set_id = parseInt(credentialSetSelect.value, 10);
            }
            payload.sudo_password = null;
        } else {
            const authType = authTypeSelect ? authTypeSelect.value : 'password';
            payload.username = usernameInput.value.trim();
            payload.auth_type = authType;
            payload.password = authType === 'password' ? passwordInput.value : '';
            payload.private_key = authType === 'key' ? privateKeyInput.value : '';
            payload.sudo_password = sudoPasswordInput && sudoPasswordInput.value ? sudoPasswordInput.value : null;
        }

        return payload;
    }

    // ------------------------------------------------------------------
    // Start scan + progress polling
    // ------------------------------------------------------------------
    function addActivity(message, type) {
        if (!scanActivity) return;
        const line = document.createElement('div');
        if (type) line.className = `text-${safeBootstrapType(type)}`;
        line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        scanActivity.appendChild(line);
        scanActivity.scrollTop = scanActivity.scrollHeight;
    }

    function resetProgressModal() {
        if (scanProgressTitle) {
            scanProgressTitle.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i> Scan in Progress';
        }
        if (scanProgressBar) {
            scanProgressBar.style.width = '0%';
            scanProgressBar.setAttribute('aria-valuenow', '0');
            scanProgressBar.classList.add('progress-bar-animated');
            scanProgressBar.classList.remove('bg-success', 'bg-danger');
        }
        if (totalIPsElement) totalIPsElement.textContent = '0';
        if (completedIPsElement) completedIPsElement.textContent = '0';
        if (remainingIPsElement) remainingIPsElement.textContent = '0';
        if (scanActivity) {
            scanActivity.innerHTML = '';
            const waiting = document.createElement('div');
            waiting.className = 'text-muted';
            waiting.textContent = 'Starting scan...';
            scanActivity.appendChild(waiting);
        }
        if (viewResultsLink) {
            viewResultsLink.classList.add('d-none');
            viewResultsLink.setAttribute('href', '#');
        }
    }

    function startScan(payload) {
        clearMessages();
        resetProgressModal();
        const originalButtonHtml = submitButton ? submitButton.innerHTML : '';
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Starting...';
        }

        apiFetch('/start_scan', { method: 'POST', json: payload })
            .then(({ ok, data }) => {
                if (ok && data.success) {
                    // Only open the progress dialog once the scan really started
                    if (scanProgressModal) scanProgressModal.show();
                    addActivity(data.message || `Scan #${data.scan_id} started`, 'info');
                    if (viewResultsLink) {
                        viewResultsLink.setAttribute('href', `/results?scan_id=${encodeURIComponent(data.scan_id)}`);
                    }
                    pollFailures = 0;
                    pollScanStatus(data.scan_id);
                } else {
                    showMessage('Error starting scan: ' + (data.error || data.message || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Error starting scan:', error);
                showMessage('Error starting scan. Please check your connection and try again.');
            })
            .finally(() => {
                if (submitButton) {
                    submitButton.disabled = false;
                    submitButton.innerHTML = originalButtonHtml;
                }
            });
    }

    function finishScan(scanId, status) {
        const failed = status === 'failed';
        if (scanProgressTitle) {
            scanProgressTitle.innerHTML = failed
                ? '<i class="fas fa-times-circle text-danger me-2"></i> Scan Failed'
                : '<i class="fas fa-check-circle text-success me-2"></i> Scan Completed';
        }
        if (scanProgressBar) {
            scanProgressBar.classList.remove('progress-bar-animated');
            scanProgressBar.classList.add(failed ? 'bg-danger' : 'bg-success');
        }
        addActivity(failed ? 'Scan finished: every host failed or the scan crashed.' : 'Scan completed.', failed ? 'danger' : 'success');
        if (viewResultsLink) {
            viewResultsLink.setAttribute('href', `/results?scan_id=${encodeURIComponent(scanId)}`);
            viewResultsLink.classList.remove('d-none');
        }
    }

    function pollScanStatus(scanId) {
        apiFetch(`/scan_status/${encodeURIComponent(scanId)}`)
            .then(({ ok, data }) => {
                if (!ok) {
                    throw new Error(data.error || 'Failed to get scan status');
                }
                pollFailures = 0;

                const total = Number(data.total) || 0;
                const completed = Number(data.completed) || 0;
                const percent = Math.max(0, Math.min(100, Number(data.percent_complete) || 0));

                if (scanProgressBar) {
                    scanProgressBar.style.width = `${percent}%`;
                    scanProgressBar.setAttribute('aria-valuenow', String(Math.round(percent)));
                }
                if (totalIPsElement) totalIPsElement.textContent = total;
                if (completedIPsElement) completedIPsElement.textContent = completed;
                if (remainingIPsElement) remainingIPsElement.textContent = Math.max(0, total - completed);

                if (data.status === 'completed' || data.status === 'failed') {
                    if (scanProgressBar) scanProgressBar.style.width = '100%';
                    finishScan(scanId, data.status);
                    return;
                }

                pollTimer = setTimeout(() => pollScanStatus(scanId), 2000);
            })
            .catch(error => {
                console.error('Error polling scan status:', error);
                pollFailures += 1;
                if (pollFailures >= 5) {
                    addActivity('Lost contact with the server. The scan may still be running; check the Results page.', 'warning');
                    if (viewResultsLink) viewResultsLink.classList.remove('d-none');
                    return;
                }
                pollTimer = setTimeout(() => pollScanStatus(scanId), 3000);
            });
    }

    if (hideProgressBtn) {
        // There is no server-side cancel; this only hides the dialog.
        hideProgressBtn.addEventListener('click', function() {
            if (pollTimer) clearTimeout(pollTimer);
            pollTimer = null;
            if (scanProgressModal) scanProgressModal.hide();
            const href = viewResultsLink ? viewResultsLink.getAttribute('href') : '#';
            if (href && href !== '#') {
                showMessage('The scan continues in the background. Open the Results page to follow it.', 'info');
            }
        });
    }

    form.addEventListener('submit', function(e) {
        e.preventDefault();
        clearMessages();
        if (!validateForm()) return;
        startScan(buildPayload());
    });

    // ------------------------------------------------------------------
    // Validate subnets
    // ------------------------------------------------------------------
    if (validateSubnetsBtn && validationResult) {
        validateSubnetsBtn.addEventListener('click', function() {
            const subnets = subnetsTextarea.value.trim();
            if (!subnets) {
                validationResult.innerHTML = '<span class="text-danger"><i class="fas fa-exclamation-circle me-1"></i> Please enter subnets</span>';
                return;
            }

            validationResult.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1"></i> Validating...</span>';
            validateSubnetsBtn.disabled = true;

            apiFetch('/validate_subnets', { method: 'POST', json: { subnets: subnets } })
                .then(({ ok, data }) => {
                    if (!ok && data.error) {
                        validationResult.innerHTML = `<span class="text-danger"><i class="fas fa-exclamation-circle me-1"></i> ${escapeHtml(data.error)}</span>`;
                        return;
                    }

                    const count = Number(data.count) || 0;
                    const sample = Array.isArray(data.sample) ? data.sample : [];
                    const errors = Array.isArray(data.errors) ? data.errors : [];
                    let html = '';

                    if (data.valid) {
                        html += `<div class="text-success"><i class="fas fa-check-circle me-1"></i> Valid: ${escapeHtml(count)} IP address${count === 1 ? '' : 'es'}</div>`;
                    } else {
                        html += `<div class="text-danger"><i class="fas fa-exclamation-circle me-1"></i> Invalid input (${escapeHtml(count)} IP address${count === 1 ? '' : 'es'} parsed`;
                        if (data.limit) html += `, limit ${escapeHtml(data.limit)}`;
                        html += ')</div>';
                    }

                    if (sample.length) {
                        const more = count > sample.length ? ` &hellip; and ${escapeHtml(count - sample.length)} more` : '';
                        html += `<div class="small text-muted mt-1">Sample: <code>${sample.map(escapeHtml).join(', ')}</code>${more}</div>`;
                    }

                    if (errors.length) {
                        html += '<ul class="small text-danger mb-0 mt-1">';
                        errors.slice(0, 20).forEach(err => {
                            html += `<li>${escapeHtml(err)}</li>`;
                        });
                        if (errors.length > 20) {
                            html += `<li>&hellip; ${escapeHtml(errors.length - 20)} more</li>`;
                        }
                        html += '</ul>';
                    }

                    validationResult.innerHTML = html;
                })
                .catch(error => {
                    console.error('Error validating subnets:', error);
                    validationResult.innerHTML = '<span class="text-danger"><i class="fas fa-exclamation-circle me-1"></i> Validation failed</span>';
                })
                .finally(() => {
                    validateSubnetsBtn.disabled = false;
                });
        });
    }

    // ------------------------------------------------------------------
    // Reset
    // ------------------------------------------------------------------
    const resetFormBtn = document.getElementById('resetForm');
    if (resetFormBtn) {
        resetFormBtn.addEventListener('click', function() {
            form.reset();
            clearMessages();
            if (validationResult) validationResult.innerHTML = '';
            toggleCredentialSections();
            toggleAuthFields();
        });
    }

    // ------------------------------------------------------------------
    // CSV import
    // ------------------------------------------------------------------
    const csvForm = document.getElementById('csvImportForm');
    const csvFileInput = document.getElementById('csvFile');
    const csvResult = document.getElementById('csvImportResult');

    function showCsvMessage(message, type) {
        if (!csvResult) return;
        csvResult.innerHTML = '';
        csvResult.appendChild(createAlert(message, type, true));
    }

    if (csvForm && csvFileInput) {
        csvForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const file = csvFileInput.files && csvFileInput.files[0];
            if (!file) {
                showCsvMessage('Please select a CSV file.', 'danger');
                return;
            }
            if (file.size > 5 * 1024 * 1024) {
                showCsvMessage('The CSV file is too large (maximum 5 MB).', 'danger');
                return;
            }

            const importBtn = csvForm.querySelector('button[type="submit"]');
            if (importBtn) importBtn.disabled = true;

            const reader = new FileReader();
            reader.onerror = function() {
                showCsvMessage('Could not read the selected file.', 'danger');
                if (importBtn) importBtn.disabled = false;
            };
            reader.onload = function() {
                apiFetch('/parse_csv', { method: 'POST', json: { csv_content: reader.result } })
                    .then(({ ok, data }) => {
                        if (ok && data.success) {
                            subnetsTextarea.value = data.subnets || '';
                            if (validationResult) validationResult.innerHTML = '';

                            // Switch back to the scan form tab
                            const manualTab = document.getElementById('manual-tab');
                            if (manualTab) bootstrap.Tab.getOrCreateInstance(manualTab).show();

                            const count = Number(data.count) || 0;
                            showMessage(`Imported ${count} IP address${count === 1 ? '' : 'es'} from ${file.name}. Review them and complete the form to start the scan.`, 'success');
                        } else {
                            showCsvMessage('CSV import failed: ' + (data.error || 'Unknown error'), 'danger');
                        }
                    })
                    .catch(error => {
                        console.error('Error importing CSV:', error);
                        showCsvMessage('CSV import failed. Please try again.', 'danger');
                    })
                    .finally(() => {
                        if (importBtn) importBtn.disabled = false;
                    });
            };
            reader.readAsText(file);
        });
    }
});
