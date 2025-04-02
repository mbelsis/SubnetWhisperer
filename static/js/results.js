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
        
        // View results buttons
        document.querySelectorAll('.view-results').forEach(button => {
            button.addEventListener('click', function() {
                const scanId = this.getAttribute('data-scan-id');
                loadScanResults(scanId);
            });
        });
        
        // Delete scan buttons
        document.querySelectorAll('.delete-scan').forEach(button => {
            button.addEventListener('click', function() {
                const scanId = this.getAttribute('data-scan-id');
                document.getElementById('deleteScanId').textContent = scanId;
                document.getElementById('confirmDeleteScan').setAttribute('data-scan-id', scanId);
                
                const deleteScanModal = new bootstrap.Modal(document.getElementById('deleteScanModal'));
                deleteScanModal.show();
            });
        });
        
        // Confirm delete scan
        document.getElementById('confirmDeleteScan').addEventListener('click', function() {
            const scanId = this.getAttribute('data-scan-id');
            deleteScan(scanId);
        });
        
        // Export buttons
        document.getElementById('exportCSV').addEventListener('click', function() {
            if (!currentScanData) return;
            
            const csvContent = convertToCSV(currentScanData);
            downloadFile(`scan_results_${document.getElementById('currentScanId').textContent}.csv`, csvContent, 'text/csv');
        });
        
        document.getElementById('exportJSON').addEventListener('click', function() {
            if (!currentScanData) return;
            
            const jsonContent = JSON.stringify(currentScanData, null, 2);
            downloadFile(`scan_results_${document.getElementById('currentScanId').textContent}.json`, jsonContent, 'application/json');
        });
        
        // Filters
        document.getElementById('statusFilter').addEventListener('change', applyFilters);
        document.getElementById('sudoFilter').addEventListener('change', applyFilters);
        document.getElementById('searchInput').addEventListener('input', applyFilters);
    }
    
    // Load scan results
    function loadScanResults(scanId) {
        // Show loading indicator
        const resultDetails = document.getElementById('resultDetails');
        resultDetails.style.display = 'block';
        resultDetails.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-primary" role="status"></div><p class="mt-3">Loading results...</p></div>';
        
        fetch(`/scan_results/${scanId}`)
            .then(response => response.json())
            .then(data => {
                // Store the scan data
                currentScanData = data.results;
                
                // Update the UI
                document.getElementById('resultDetails').style.display = 'block';
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
                document.getElementById('resultDetails').innerHTML = `
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-circle me-2"></i> Failed to load scan results.
                    </div>
                `;
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
                <td>${result.ip_address}</td>
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
                <td>${formatExecutionTime(result.execution_time)}</td>
                <td>
                    <button type="button" class="btn btn-sm btn-primary view-result" data-result-id="${result.id}">
                        <i class="fas fa-eye"></i>
                    </button>
                </td>
            `;
            
            tableBody.appendChild(row);
        });
        
        // Initialize DataTable if not already initialized
        if (resultsTable) {
            resultsTable.destroy();
        }
        
        resultsTable = new DataTable('#resultsTable', {
            responsive: true,
            order: [[0, 'asc']], // Sort by IP address ascending
            language: {
                search: "Filter:"
            }
        });
        
        // Add event listeners to view result buttons
        document.querySelectorAll('.view-result').forEach(button => {
            button.addEventListener('click', function() {
                const resultId = this.getAttribute('data-result-id');
                showResultDetails(resultId);
            });
        });
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
    
    // Show result details
    function showResultDetails(resultId) {
        if (!currentScanData) return;
        
        const result = currentScanData.find(r => r.id === parseInt(resultId));
        if (!result) return;
        
        document.getElementById('detailsIpAddress').textContent = result.ip_address;
        
        // Populate command output
        let commandOutput = '';
        if (result.command_output) {
            try {
                const commands = JSON.parse(result.command_output);
                commandOutput = '<div class="accordion" id="commandOutputAccordion">';
                
                commands.forEach((cmd, index) => {
                    const headerId = `heading${index}`;
                    const collapseId = `collapse${index}`;
                    const isFirst = index === 0;
                    const statusClass = cmd.success ? 'text-success' : 'text-danger';
                    const statusIcon = cmd.success ? 'check-circle' : 'times-circle';
                    
                    commandOutput += `
                        <div class="accordion-item">
                            <h2 class="accordion-header" id="${headerId}">
                                <button class="accordion-button ${isFirst ? '' : 'collapsed'}" type="button" 
                                        data-bs-toggle="collapse" data-bs-target="#${collapseId}" 
                                        aria-expanded="${isFirst ? 'true' : 'false'}" aria-controls="${collapseId}">
                                    <i class="fas fa-${statusIcon} ${statusClass} me-2"></i>
                                    <code>${cmd.command}</code>
                                    <span class="ms-auto badge ${cmd.success ? 'bg-success' : 'bg-danger'}">
                                        Exit: ${cmd.exit_status}
                                    </span>
                                </button>
                            </h2>
                            <div id="${collapseId}" class="accordion-collapse collapse ${isFirst ? 'show' : ''}" 
                                 aria-labelledby="${headerId}" data-bs-parent="#commandOutputAccordion">
                                <div class="accordion-body">
                                    <div class="mb-3">
                                        <h6>Standard Output:</h6>
                                        <pre class="bg-dark text-light p-2 rounded">${cmd.stdout || '<i class="text-muted">No output</i>'}</pre>
                                    </div>
                                    ${cmd.stderr ? `
                                    <div>
                                        <h6>Standard Error:</h6>
                                        <pre class="bg-dark text-light p-2 rounded">${cmd.stderr}</pre>
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
                <pre class="bg-dark text-light p-2 rounded">${result.command_output}</pre>`;
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
                const serverInfo = JSON.parse(result.server_info);
                
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
                                            <code>${serverInfo.hostname}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Kernel</span>
                                            <code>${serverInfo.kernel || 'N/A'}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Uptime</span>
                                            <code>${serverInfo.uptime || 'N/A'}</code>
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
                                            <code>${serverInfo.os.PRETTY_NAME || serverInfo.os.NAME || 'N/A'}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Version</span>
                                            <code>${serverInfo.os.VERSION_ID || 'N/A'}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>ID</span>
                                            <code>${serverInfo.os.ID || 'N/A'}</code>
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
                                            <code>${serverInfo.cpu['Model name'] || 'N/A'}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>CPUs</span>
                                            <code>${serverInfo.cpu['CPU(s)'] || 'N/A'}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Architecture</span>
                                            <code>${serverInfo.cpu['Architecture'] || 'N/A'}</code>
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
                                            <code>${serverInfo.memory.total}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Used</span>
                                            <code>${serverInfo.memory.used}</code>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span>Free</span>
                                            <code>${serverInfo.memory.free}</code>
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
                        const diskParts = serverInfo.disk[i].split(/\s+/);
                        if (diskParts.length >= 6) {
                            serverInfoHtml += `
                                <tr>
                                    <td>${diskParts[0]}</td>
                                    <td>${diskParts[1]}</td>
                                    <td>${diskParts[2]}</td>
                                    <td>${diskParts[3]}</td>
                                    <td>${diskParts[4]}</td>
                                    <td>${diskParts[5]}</td>
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
                                            <h6 class="mb-0">${iface.ifname}</h6>
                                        </div>
                                        <div class="card-body">
                                            <ul class="list-group list-group-flush">
                                `;
                                
                                if (iface.addr_info) {
                                    iface.addr_info.forEach(addr => {
                                        networkInfo += `
                                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                                <span>${addr.family}</span>
                                                <code>${addr.local}/${addr.prefixlen}</code>
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
                        networkInfo = `<pre class="bg-dark text-light p-2 rounded">${serverInfo.network}</pre>`;
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
                
            } catch (e) {
                serverInfoHtml = `
                    <div class="col-12">
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle me-2"></i> Failed to parse server information.
                        </div>
                        <pre class="bg-dark text-light p-2 rounded">${result.server_info}</pre>
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
            document.getElementById('errorContainer').innerHTML = result.error_message;
        } else {
            document.getElementById('errorContainer').innerHTML = '<i class="text-muted">No errors reported.</i>';
        }
        
        // Show the modal
        const modal = new bootstrap.Modal(document.getElementById('resultDetailsModal'));
        modal.show();
    }
    
    // Delete a scan
    function deleteScan(scanId) {
        fetch(`/api/delete_scan/${scanId}`, {
            method: 'DELETE'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Hide the modal
                bootstrap.Modal.getInstance(document.getElementById('deleteScanModal')).hide();
                
                // Remove the row from the table
                scanSessionsTable.row(`tr[data-scan-id="${scanId}"]`).remove().draw();
                
                // If current results are from the deleted scan, hide them
                if (document.getElementById('currentScanId').textContent === scanId) {
                    document.getElementById('resultDetails').style.display = 'none';
                }
                
                showToast('Scan deleted successfully', 'Success', 'success');
            } else {
                showToast(data.error || 'Failed to delete scan', 'Error', 'danger');
            }
        })
        .catch(error => {
            console.error('Error deleting scan:', error);
            showToast('Failed to delete scan', 'Error', 'danger');
        });
    }
});
