/**
 * Subnet Whisperer - Results Page JavaScript
 * Functionality for viewing and analyzing scan results
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize DataTable for scan sessions
    const scanSessionsTable = new DataTable('#scanSessionsTable', {
        order: [[1, 'desc']], // Sort by started date descending
        language: {
            emptyTable: "No scan sessions found"
        },
        columnDefs: [
            { width: "5%", targets: 0 }, // ID
            { width: "15%", targets: 1 }, // Started
            { width: "10%", targets: 2 }, // Username
            { width: "10%", targets: 3 }, // Auth Type
            { width: "10%", targets: 4 }, // Status
            { width: "10%", targets: 5 }, // Success
            { width: "10%", targets: 6 }, // Failed
            { width: "10%", targets: 7 }, // Total
            { width: "10%", targets: 8 }, // Actions
        ]
    });
    
    // Helpers for values that may arrive either as JSON strings or as
    // already-parsed objects (ScanResult.to_dict() returns parsed values).
    function parseMaybeJson(value) {
        return typeof value === 'string' ? JSON.parse(value) : value;
    }

    function stringifyMaybe(value) {
        if (typeof value === 'string') return value;
        try {
            return JSON.stringify(value, null, 2);
        } catch (e) {
            return String(value);
        }
    }

    // Results table will be initialized when needed
    let resultsTable;
    
    // Charts
    let successRateChart;
    let executionTimeChart;
    
    // Current scan data
    let currentScanData = null;
    
    // Initialize event handlers
    initializeEventHandlers();
    
    // Show details for current scan if any
    const currentScanId = new URLSearchParams(window.location.search).get('scan_id');
    if (currentScanId) {
        loadScanResults(currentScanId);
    }
    
    // Initialize event handlers
    function initializeEventHandlers() {
        // Refresh scans button
        document.getElementById('refreshScans').addEventListener('click', function() {
            window.location.reload();
        });
        
        // View / delete buttons (delegated so they work on every DataTable page).
        // Delete buttons are only rendered for admins.
        document.getElementById('scanSessionsTable').addEventListener('click', function(e) {
            const viewButton = e.target.closest('.view-results');
            if (viewButton) {
                loadScanResults(viewButton.getAttribute('data-scan-id'));
                return;
            }

            const deleteButton = e.target.closest('.delete-scan');
            if (deleteButton) {
                const scanId = deleteButton.getAttribute('data-scan-id');
                document.getElementById('deleteScanId').textContent = scanId;
                document.getElementById('confirmDeleteScan').setAttribute('data-scan-id', scanId);
                
                const deleteScanModal = bootstrap.Modal.getOrCreateInstance(document.getElementById('deleteScanModal'));
                deleteScanModal.show();
            }
        });
        
        // Confirm delete scan
        const confirmDeleteScanBtn = document.getElementById('confirmDeleteScan');
        if (confirmDeleteScanBtn) {
            confirmDeleteScanBtn.addEventListener('click', function() {
                const scanId = this.getAttribute('data-scan-id');
                deleteScan(scanId);
            });
        }
        
        // Export buttons
        document.getElementById('exportCSV').addEventListener('click', function() {
            if (!currentScanData) return;
            
            const scanId = document.getElementById('currentScanId').textContent;
            window.location.href = `/scan_results/${encodeURIComponent(scanId)}/export/csv`;
        });

        document.getElementById('exportJSON').addEventListener('click', function() {
            if (!currentScanData) return;

            // The server export includes command output and server info
            const scanId = document.getElementById('currentScanId').textContent;
            window.location.href = `/scan_results/${encodeURIComponent(scanId)}/export/json`;
        });
        
        document.getElementById('exportPDF').addEventListener('click', function() {
            if (!currentScanData) return;
            
            const scanId = document.getElementById('currentScanId').textContent;
            window.location.href = `/scan_results/${encodeURIComponent(scanId)}/export/pdf`;
        });
        
        // Filters
        document.getElementById('statusFilter').addEventListener('change', applyFilters);
        document.getElementById('sudoFilter').addEventListener('change', applyFilters);
        document.getElementById('searchInput').addEventListener('input', applyFilters);
    }
    
    // Load scan results
    function loadScanResults(scanId) {
        // Show loading indicator (without destroying the results markup)
        const resultDetails = document.getElementById('resultDetails');
        const resultStatus = document.getElementById('resultLoadStatus');
        if (resultStatus) {
            resultStatus.style.display = 'block';
            resultStatus.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-primary" role="status"></div><p class="mt-3">Loading results...</p></div>';
        }
        
        apiFetch(`/scan_results/${encodeURIComponent(scanId)}`)
            .then(({ ok, data }) => {
                if (!ok) {
                    throw new Error(data.error || 'Failed to load scan results');
                }
                if (resultStatus) {
                    resultStatus.style.display = 'none';
                    resultStatus.innerHTML = '';
                }

                // Store the scan data
                currentScanData = data.results || [];
                
                // Update the UI
                resultDetails.style.display = 'block';
                document.getElementById('currentScanId').textContent = scanId;
                
                updateScanSummary(data.results);
                
                // Populate the results table
                populateResultsTable(data.results);
                
                // Create charts
                createCharts(data.results);
                
                // Scroll to results
                document.getElementById('resultDetails').scrollIntoView({
                    behavior: 'smooth'
                });
            })
            .catch(error => {
                console.error('Error loading scan results:', error);
                resultDetails.style.display = 'none';
                if (resultStatus) {
                    resultStatus.style.display = 'block';
                    resultStatus.innerHTML = `
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-circle me-2"></i> Failed to load scan results: ${escapeHtml(error.message)}
                        </div>
                    `;
                }
            });
    }
    
    // Update scan summary
    function updateScanSummary(results) {
        if (!results || results.length === 0) {
            document.getElementById('totalHosts').textContent = '0';
            document.getElementById('sshSuccess').textContent = '0';
            document.getElementById('sudoSuccess').textContent = '0';
            document.getElementById('failedHosts').textContent = '0';
            return;
        }
        
        const totalHosts = results.length;
        const sshSuccess = results.filter(r => r.ssh_status === true).length;
        const sudoSuccess = results.filter(r => r.sudo_status === true).length;
        const failedHosts = results.filter(r => r.status_code === 'failed').length;
        
        document.getElementById('totalHosts').textContent = totalHosts;
        document.getElementById('sshSuccess').textContent = sshSuccess;
        document.getElementById('sudoSuccess').textContent = sudoSuccess;
        document.getElementById('failedHosts').textContent = failedHosts;
    }
    
    // Populate results table
    function populateResultsTable(results) {
        const tableBody = document.getElementById('resultsTableBody');
        // Destroy any previous DataTable before touching the rows
        if (resultsTable) {
            resultsTable.destroy();
            resultsTable = null;
        }
        tableBody.innerHTML = '';
        
        if (!results || results.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="7" class="text-center">No results found</td></tr>`;
            return;
        }
        
        results.forEach(result => {
            const row = document.createElement('tr');
            
            // Status styling
            if (result.status_code === 'success') {
                row.classList.add('table-success');
            } else if (result.status_code === 'failed') {
                row.classList.add('table-danger');
            }
            
            row.innerHTML = `
                <td>${escapeHtml(result.ip_address)}</td>
                <td>
                    ${result.status_code === 'success' 
                        ? '<span class="badge bg-success">Success</span>' 
                        : '<span class="badge bg-danger">Failed</span>'}
                </td>
                <td>
                    ${result.ssh_status 
                        ? '<span class="badge bg-success"><i class="fas fa-check"></i></span>' 
                        : '<span class="badge bg-danger"><i class="fas fa-times"></i></span>'}
                </td>
                <td>
                    ${result.sudo_status 
                        ? '<span class="badge bg-success"><i class="fas fa-check"></i></span>' 
                        : '<span class="badge bg-danger"><i class="fas fa-times"></i></span>'}
                </td>
                <td>
                    ${result.command_status 
                        ? '<span class="badge bg-success"><i class="fas fa-check"></i></span>' 
                        : '<span class="badge bg-danger"><i class="fas fa-times"></i></span>'}
                </td>
                <td>${escapeHtml(formatExecutionTime(result.execution_time))}</td>
                <td>
                    <button type="button" class="btn btn-sm btn-primary view-result" data-result-id="${escapeHtml(result.id)}">
                        <i class="fas fa-eye"></i>
                    </button>
                </td>
            `;
            
            tableBody.appendChild(row);
        });
        
        resultsTable = new DataTable('#resultsTable', {
            responsive: true,
            order: [[0, 'asc']], // Sort by IP address ascending
            language: {
                search: "Filter:"
            }
        });
        
        // Delegate clicks so buttons on other DataTable pages work too
        tableBody.onclick = function(e) {
            const button = e.target.closest('.view-result');
            if (button) {
                showResultDetails(button.getAttribute('data-result-id'));
            }
        };
    }
    
    // Create charts
    function createCharts(results) {
        // Destroy existing charts if they exist
        if (successRateChart) {
            successRateChart.destroy();
        }
        
        if (executionTimeChart) {
            executionTimeChart.destroy();
        }
        
        // Success Rate Chart
        const successCount = results.filter(r => r.status_code === 'success').length;
        const failedCount = results.filter(r => r.status_code === 'failed').length;
        
        const successRateCtx = document.getElementById('successRateChart').getContext('2d');
        successRateChart = new Chart(successRateCtx, {
            type: 'pie',
            data: {
                labels: ['Success', 'Failed'],
                datasets: [{
                    data: [successCount, failedCount],
                    backgroundColor: ['#198754', '#dc3545'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
        
        // Execution Time Chart
        // Group by time ranges
        const timeRanges = {
            'Under 1s': 0,
            '1-5s': 0,
            '5-10s': 0,
            '10-30s': 0,
            'Over 30s': 0
        };
        
        results.forEach(result => {
            const time = result.execution_time || 0;
            
            if (time < 1) {
                timeRanges['Under 1s']++;
            } else if (time < 5) {
                timeRanges['1-5s']++;
            } else if (time < 10) {
                timeRanges['5-10s']++;
            } else if (time < 30) {
                timeRanges['10-30s']++;
            } else {
                timeRanges['Over 30s']++;
            }
        });
        
        const executionTimeCtx = document.getElementById('executionTimeChart').getContext('2d');
        executionTimeChart = new Chart(executionTimeCtx, {
            type: 'bar',
            data: {
                labels: Object.keys(timeRanges),
                datasets: [{
                    label: 'Hosts',
                    data: Object.values(timeRanges),
                    backgroundColor: '#0d6efd',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of Hosts'
                        },
                        ticks: {
                            precision: 0
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Execution Time'
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }
    
    // Apply filters to results table
    function applyFilters() {
        const statusFilter = document.getElementById('statusFilter').value;
        const sudoFilter = document.getElementById('sudoFilter').value;
        const searchFilter = document.getElementById('searchInput').value.toLowerCase();
        
        if (!resultsTable) return;
        
        // Clear all filters
        resultsTable.search('').columns().search('').draw();
        
        // Apply custom filtering
        $.fn.dataTable.ext.search.push(
            function(settings, data, dataIndex) {
                // Skip if not the results table
                if (settings.nTable.id !== 'resultsTable') return true;
                
                const statusValue = data[1].toLowerCase().includes('success') ? 'success' : 'failed';
                const sudoValue = data[3].toLowerCase().includes('check') ? 'yes' : 'no';
                const ipAndOutput = data[0].toLowerCase();
                
                // Status filter
                const statusMatch = statusFilter === 'all' || statusFilter === statusValue;
                
                // Sudo filter
                const sudoMatch = sudoFilter === 'all' || 
                                 (sudoFilter === 'yes' && sudoValue === 'yes') || 
                                 (sudoFilter === 'no' && sudoValue === 'no');
                
                // Search filter
                const searchMatch = searchFilter === '' || ipAndOutput.includes(searchFilter);
                
                return statusMatch && sudoMatch && searchMatch;
            }
        );
        
        // Redraw the table with filters applied
        resultsTable.draw();
        
        // Remove the custom filter function to prevent it from stacking
        $.fn.dataTable.ext.search.pop();
    }
    
    // Show result details (the result list has no output; fetch the full record)
    function showResultDetails(resultId) {
        if (!currentScanData) return;

        const summary = currentScanData.find(r => r.id === parseInt(resultId));
        if (!summary) return;

        apiFetch(`/scan_results/${encodeURIComponent(summary.scan_session_id)}/result/${encodeURIComponent(summary.id)}`)
            .then(({ ok, data }) => {
                if (!ok) {
                    throw new Error(data.error || 'Failed to load result details');
                }
                renderResultDetails(data);
            })
            .catch(error => {
                console.error('Error loading result details:', error);
                showToast(error.message || 'Failed to load result details', 'Error', 'danger');
            });
    }

    function renderResultDetails(result) {
        document.getElementById('detailsIpAddress').textContent = result.ip_address;
        
        // Populate command output (may arrive as a JSON string or as a parsed list)
        let commandOutput = '';
        if (result.command_output) {
            try {
                const commands = parseMaybeJson(result.command_output);
                if (!Array.isArray(commands)) {
                    throw new Error('command_output is not a list');
                }
                commandOutput = '<div class="accordion" id="commandOutputAccordion">';
                
                commands.forEach((cmd, index) => {
                    const headerId = `heading${index}`;
                    const collapseId = `collapse${index}`;
                    const isFirst = index === 0;
                    cmd = cmd || {};
                    const statusClass = cmd.success ? 'text-success' : 'text-danger';
                    const statusIcon = cmd.success ? 'check-circle' : 'times-circle';
                    
                    commandOutput += `
                        <div class="accordion-item">
                            <h2 class="accordion-header" id="${headerId}">
                                <button class="accordion-button ${isFirst ? '' : 'collapsed'}" type="button" 
                                        data-bs-toggle="collapse" data-bs-target="#${collapseId}" 
                                        aria-expanded="${isFirst ? 'true' : 'false'}" aria-controls="${collapseId}">
                                    <i class="fas fa-${statusIcon} ${statusClass} me-2"></i>
                                    <code>${escapeHtml(cmd.command)}</code>
                                    ${cmd.security_blocked ? '<span class="ms-2 badge bg-warning text-dark">Blocked</span>' : ''}
                                    <span class="ms-auto badge ${cmd.success ? 'bg-success' : 'bg-danger'}">
                                        Exit: ${escapeHtml(cmd.exit_status)}
                                    </span>
                                </button>
                            </h2>
                            <div id="${collapseId}" class="accordion-collapse collapse ${isFirst ? 'show' : ''}" 
                                 aria-labelledby="${headerId}" data-bs-parent="#commandOutputAccordion">
                                <div class="accordion-body">
                                    <div class="mb-3">
                                        <h6>Standard Output:</h6>
                                        <pre class="bg-dark text-light p-2 rounded">${cmd.stdout ? escapeHtml(cmd.stdout) : '<i class="text-muted">No output</i>'}</pre>
                                    </div>
                                    ${cmd.stderr ? `
                                    <div>
                                        <h6>Standard Error:</h6>
                                        <pre class="bg-dark text-light p-2 rounded">${escapeHtml(cmd.stderr)}</pre>
                                    </div>
                                    ` : ''}
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                commandOutput += '</div>';
            } catch (e) {
                commandOutput = `<div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle me-2"></i> Failed to parse command output.
                </div>
                <pre class="bg-dark text-light p-2 rounded">${escapeHtml(stringifyMaybe(result.command_output))}</pre>`;
            }
        } else {
            commandOutput = `<div class="alert alert-info">
                <i class="fas fa-info-circle me-2"></i> No command output available.
            </div>`;
        }
        
        document.getElementById('commandOutputContainer').innerHTML = commandOutput;
        
        // Populate server info
        let serverInfoHtml = '';
        if (result.server_info) {
            try {
                const serverInfo = parseMaybeJson(result.server_info);
                if (!serverInfo || typeof serverInfo !== 'object' || Array.isArray(serverInfo)) {
                    throw new Error('server_info is not an object');
                }
                
                // Hostname
                if (serverInfo.hostname) {
                    serverInfoHtml += `
                        <div class="col-md-6 mb-3">
                            <div class="card h-100">
                                <div class="card-header">
                                    <h6 class="mb-0"><i class="fas fa-server me-2"></i> System Information</h6>
                                </div>
                                <div class="card-body">
                                    <ul class="list-group list-group-flush">
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Hostname</span>
                                            <code>${escapeHtml(serverInfo.hostname)}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Kernel</span>
                                            <code>${escapeHtml(serverInfo.kernel || 'N/A')}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Uptime</span>
                                            <code>${escapeHtml(serverInfo.uptime || 'N/A')}</code>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    `;
                }
                
                // OS Information
                if (serverInfo.os) {
                    serverInfoHtml += `
                        <div class="col-md-6 mb-3">
                            <div class="card h-100">
                                <div class="card-header">
                                    <h6 class="mb-0"><i class="fas fa-desktop me-2"></i> Operating System</h6>
                                </div>
                                <div class="card-body">
                                    <ul class="list-group list-group-flush">
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Name</span>
                                            <code>${escapeHtml(serverInfo.os.PRETTY_NAME || serverInfo.os.NAME || 'N/A')}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Version</span>
                                            <code>${escapeHtml(serverInfo.os.VERSION_ID || 'N/A')}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>ID</span>
                                            <code>${escapeHtml(serverInfo.os.ID || 'N/A')}</code>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    `;
                }
                
                // CPU Information
                if (serverInfo.cpu) {
                    serverInfoHtml += `
                        <div class="col-md-6 mb-3">
                            <div class="card h-100">
                                <div class="card-header">
                                    <h6 class="mb-0"><i class="fas fa-microchip me-2"></i> CPU Information</h6>
                                </div>
                                <div class="card-body">
                                    <ul class="list-group list-group-flush">
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Model</span>
                                            <code>${escapeHtml(serverInfo.cpu['Model name'] || 'N/A')}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>CPUs</span>
                                            <code>${escapeHtml(serverInfo.cpu['CPU(s)'] || 'N/A')}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Architecture</span>
                                            <code>${escapeHtml(serverInfo.cpu['Architecture'] || 'N/A')}</code>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    `;
                }
                
                // Memory Information
                if (serverInfo.memory) {
                    serverInfoHtml += `
                        <div class="col-md-6 mb-3">
                            <div class="card h-100">
                                <div class="card-header">
                                    <h6 class="mb-0"><i class="fas fa-memory me-2"></i> Memory Information</h6>
                                </div>
                                <div class="card-body">
                                    <ul class="list-group list-group-flush">
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Total</span>
                                            <code>${escapeHtml(serverInfo.memory.total)}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Used</span>
                                            <code>${escapeHtml(serverInfo.memory.used)}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Free</span>
                                            <code>${escapeHtml(serverInfo.memory.free)}</code>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    `;
                }
                
                // Disk Information
                if (serverInfo.disk && serverInfo.disk.length > 1) {
                    serverInfoHtml += `
                        <div class="col-md-12 mb-3">
                            <div class="card">
                                <div class="card-header">
                                    <h6 class="mb-0"><i class="fas fa-hdd me-2"></i> Disk Information</h6>
                                </div>
                                <div class="card-body">
                                    <div class="table-responsive">
                                        <table class="table table-hover">
                                            <thead>
                                                <tr>
                                                    <th>Filesystem</th>
                                                    <th>Size</th>
                                                    <th>Used</th>
                                                    <th>Available</th>
                                                    <th>Use%</th>
                                                    <th>Mounted on</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                    `;
                    
                    // Skip the header row
                    for (let i = 1; i < serverInfo.disk.length; i++) {
                        const diskParts = String(serverInfo.disk[i]).split(/\s+/);
                        if (diskParts.length >= 6) {
                            serverInfoHtml += `
                                <tr>
                                    <td>${escapeHtml(diskParts[0])}</td>
                                    <td>${escapeHtml(diskParts[1])}</td>
                                    <td>${escapeHtml(diskParts[2])}</td>
                                    <td>${escapeHtml(diskParts[3])}</td>
                                    <td>${escapeHtml(diskParts[4])}</td>
                                    <td>${escapeHtml(diskParts[5])}</td>
                                </tr>
                            `;
                        }
                    }
                    
                    serverInfoHtml += `
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                }
                
                // Network Information
                if (serverInfo.network) {
                    let networkInfo = '';
                    
                    if (Array.isArray(serverInfo.network)) {
                        // JSON format
                        serverInfo.network.forEach(iface => {
                            if (iface.ifname && iface.ifname !== 'lo') {
                                networkInfo += `
                                    <div class="card mb-3">
                                        <div class="card-header">
                                            <h6 class="mb-0">${escapeHtml(iface.ifname)}</h6>
                                        </div>
                                        <div class="card-body">
                                            <ul class="list-group list-group-flush">
                                `;
                                
                                if (iface.addr_info) {
                                    iface.addr_info.forEach(addr => {
                                        networkInfo += `
                                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                                <span>${escapeHtml(addr.family)}</span>
                                                <code>${escapeHtml(addr.local)}/${escapeHtml(addr.prefixlen)}</code>
                                            </li>
                                        `;
                                    });
                                }
                                
                                networkInfo += `
                                            </ul>
                                        </div>
                                    </div>
                                `;
                            }
                        });
                    } else if (typeof serverInfo.network === 'string') {
                        // Plain text format
                        networkInfo = `<pre class="bg-dark text-light p-2 rounded">${escapeHtml(serverInfo.network)}</pre>`;
                    }
                    
                    if (networkInfo) {
                        serverInfoHtml += `
                            <div class="col-md-12 mb-3">
                                <div class="card">
                                    <div class="card-header">
                                        <h6 class="mb-0"><i class="fas fa-network-wired me-2"></i> Network Information</h6>
                                    </div>
                                    <div class="card-body">
                                        ${networkInfo}
                                    </div>
                                </div>
                            </div>
                        `;
                    }
                }
                
                // Detailed Server Information Cards
                if (serverInfo.dns_config && Array.isArray(serverInfo.dns_config)) {
                    serverInfoHtml += `
                        <div class="col-md-6 mb-3">
                            <div class="card h-100">
                                <div class="card-header">
                                    <h6 class="mb-0"><i class="fas fa-dns me-2"></i> DNS Configuration</h6>
                                </div>
                                <div class="card-body">
                                    <pre class="bg-dark text-light p-2 rounded small">${escapeHtml(serverInfo.dns_config.join('\n'))}</pre>
                                </div>
                            </div>
                        </div>
                    `;
                }
                
                if (serverInfo.running_services && Array.isArray(serverInfo.running_services)) {
                    // Get first 15 services max to avoid overwhelming the UI
                    const services = serverInfo.running_services.slice(0, 15);
                    
                    serverInfoHtml += `
                        <div class="col-md-6 mb-3">
                            <div class="card h-100">
                                <div class="card-header">
                                    <h6 class="mb-0"><i class="fas fa-cogs me-2"></i> Running Services</h6>
                                </div>
                                <div class="card-body">
                                    <div class="table-responsive">
                                        <table class="table table-sm">
                                            <thead>
                                                <tr>
                                                    <th>Service</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                ${services.map(service => `<tr><td class="small">${escapeHtml(typeof service === 'string' ? service : JSON.stringify(service))}</td></tr>`).join('')}
                                            </tbody>
                                        </table>
                                    </div>
                                    ${serverInfo.running_services.length > 15 ? `<small class="text-muted">Showing 15 of ${escapeHtml(serverInfo.running_services.length)} services</small>` : ''}
                                </div>
                            </div>
                        </div>
                    `;
                }
                
                if (serverInfo.network_connections && Array.isArray(serverInfo.network_connections)) {
                    serverInfoHtml += `
                        <div class="col-md-6 mb-3">
                            <div class="card h-100">
                                <div class="card-header">
                                    <h6 class="mb-0"><i class="fas fa-exchange-alt me-2"></i> Network Connections</h6>
                                </div>
                                <div class="card-body">
                                    <pre class="bg-dark text-light p-2 rounded small">${escapeHtml(serverInfo.network_connections.join('\n'))}</pre>
                                </div>
                            </div>
                        </div>
                    `;
                }
                
                if (serverInfo.ethernet_cards && Array.isArray(serverInfo.ethernet_cards)) {
                    serverInfoHtml += `
                        <div class="col-md-6 mb-3">
                            <div class="card h-100">
                                <div class="card-header">
                                    <h6 class="mb-0"><i class="fas fa-network-wired me-2"></i> Network Cards</h6>
                                </div>
                                <div class="card-body">
                                    <pre class="bg-dark text-light p-2 rounded small">${escapeHtml(serverInfo.ethernet_cards.join('\n'))}</pre>
                                </div>
                            </div>
                        </div>
                    `;
                }
                
                if (serverInfo.default_gateway) {
                    serverInfoHtml += `
                        <div class="col-md-6 mb-3">
                            <div class="card h-100">
                                <div class="card-header">
                                    <h6 class="mb-0"><i class="fas fa-route me-2"></i> Default Gateway</h6>
                                </div>
                                <div class="card-body">
                                    <pre class="bg-dark text-light p-2 rounded">${escapeHtml(serverInfo.default_gateway)}</pre>
                                </div>
                            </div>
                        </div>
                    `;
                }
                
                if (serverInfo.virtualization) {
                    serverInfoHtml += `
                        <div class="col-md-6 mb-3">
                            <div class="card h-100">
                                <div class="card-header">
                                    <h6 class="mb-0"><i class="fas fa-cloud me-2"></i> Virtualization</h6>
                                </div>
                                <div class="card-body">
                                    <pre class="bg-dark text-light p-2 rounded">${escapeHtml(serverInfo.virtualization)}</pre>
                                </div>
                            </div>
                        </div>
                    `;
                }

                // Remaining detailed sections rendered as plain text blocks
                const textSections = [
                    ['load_average', 'fa-tachometer-alt', 'Load Average'],
                    ['user_accounts', 'fa-users', 'User Accounts (login shells)'],
                    ['firewall_rules', 'fa-shield-alt', 'Firewall Rules'],
                    ['installed_packages', 'fa-box', 'Installed Packages (first 100)'],
                ];
                textSections.forEach(([key, icon, title]) => {
                    const value = serverInfo[key];
                    if (value === undefined || value === null) return;
                    const lines = Array.isArray(value) ? value.filter(line => String(line).trim() !== '') : [String(value)];
                    const body = lines.length
                        ? `<pre class="bg-dark text-light p-2 rounded small" style="max-height: 300px; overflow: auto;">${escapeHtml(lines.join('\n'))}</pre>`
                        : '<p class="text-muted mb-0">Not available on this host (the tool may be missing or need root access).</p>';
                    serverInfoHtml += `
                        <div class="col-md-6 mb-3">
                            <div class="card h-100">
                                <div class="card-header">
                                    <h6 class="mb-0"><i class="fas ${icon} me-2"></i> ${escapeHtml(title)}</h6>
                                </div>
                                <div class="card-body">${body}</div>
                            </div>
                        </div>
                    `;
                });

            } catch (e) {
                serverInfoHtml = `
                    <div class="col-12">
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle me-2"></i> Failed to parse server information.
                        </div>
                        <pre class="bg-dark text-light p-2 rounded">${escapeHtml(stringifyMaybe(result.server_info))}</pre>
                    </div>
                `;
            }
        } else {
            serverInfoHtml = `
                <div class="col-12">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i> No server information available.
                    </div>
                </div>
            `;
        }
        
        document.getElementById('serverInfoContainer').innerHTML = serverInfoHtml;
        
        // Populate error message
        if (result.error_message) {
            document.getElementById('errorContainer').textContent = result.error_message;
        } else {
            document.getElementById('errorContainer').innerHTML = '<i class="text-muted">No errors reported.</i>';
        }
        
        // Show the modal
        const modal = new bootstrap.Modal(document.getElementById('resultDetailsModal'));
        modal.show();
    }
    
    // Delete a scan
    function deleteScan(scanId) {
        const modalInstance = bootstrap.Modal.getInstance(document.getElementById('deleteScanModal'));
        apiFetch(`/api/delete_scan/${encodeURIComponent(scanId)}`, {
            method: 'DELETE'
        })
        .then(({ ok, status, data }) => {
            if (modalInstance) modalInstance.hide();

            if (ok && data.success) {
                // Remove the row from the table
                const row = document.querySelector(`#scanSessionsTable tr[data-scan-id="${CSS.escape(String(scanId))}"]`);
                if (row) {
                    scanSessionsTable.row(row).remove().draw();
                }
                
                // If current results are from the deleted scan, hide them
                if (document.getElementById('currentScanId').textContent === String(scanId)) {
                    document.getElementById('resultDetails').style.display = 'none';
                    currentScanData = null;
                }
                
                showToast('Scan deleted successfully', 'Success', 'success');
            } else if (status === 403) {
                showToast('You are not allowed to delete scans. Ask an administrator.', 'Not allowed', 'danger');
            } else if (status === 404) {
                showToast(data.error || 'Scan not found', 'Error', 'danger');
            } else {
                showToast(data.error || 'Failed to delete scan', 'Error', 'danger');
            }
        })
        .catch(error => {
            console.error('Error deleting scan:', error);
            showToast('Failed to delete scan', 'Error', 'danger');
        });
    }

    // Format execution time for display
    function formatExecutionTime(time) {
        if (!time) return 'N/A';
        return time < 1 ? `${Math.round(time * 1000)}ms` : `${time.toFixed(2)}s`;
    }

});
