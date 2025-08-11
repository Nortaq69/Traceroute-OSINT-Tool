// Traceroute OSINT Tool JavaScript
// Modern, polished implementation with enhanced UX and error handling

/**
 * Main Traceroute OSINT Tool class
 */
class TracerouteOSINTTool {
    constructor() {
        this.currentResults = null;
        this.isRunning = false;
        this.analysisCache = new Map();
        this.exportHistory = [];
        this.initializeTool();
    }

    /**
     * Initialize the tool and set up event listeners
     */
    initializeTool() {
        document.addEventListener('DOMContentLoaded', () => {
            this.setupEventListeners();
            this.showToast('Traceroute OSINT Tool ready', 'info');
        });
    }

    /**
     * Set up all event listeners
     */
    setupEventListeners() {
        // Target input with Enter key support
        const targetInput = document.getElementById('target');
        if (targetInput) {
            targetInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.startTraceroute();
                }
            });
            
            // Add input validation
            targetInput.addEventListener('input', (e) => {
                this.validateTarget(e.target.value);
            });
        }

        // Form submission
        const form = document.querySelector('form');
        if (form) {
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                this.startTraceroute();
            });
        }

        // Export buttons
        document.querySelectorAll('[data-export]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const format = e.target.dataset.export;
                this.exportResults(format);
            });
        });

        // Tab switching
        document.querySelectorAll('[data-tab]').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabName = e.target.dataset.tab;
                this.showTab(tabName);
            });
        });

        // Clear results
        const clearBtn = document.getElementById('clearResults');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clearResults());
        }

        // Copy to clipboard
        const copyBtn = document.getElementById('copyResults');
        if (copyBtn) {
            copyBtn.addEventListener('click', () => this.copyToClipboard());
        }
    }

    /**
     * Validate target input
     */
    validateTarget(value) {
        const targetInput = document.getElementById('target');
        const validationMsg = document.getElementById('targetValidation');
        
        if (!targetInput || !validationMsg) return;
        
        const trimmed = value.trim();
        let isValid = false;
        let message = '';
        
        if (!trimmed) {
            message = '';
        } else if (this.isValidIP(trimmed)) {
            isValid = true;
            message = '✓ Valid IP address';
        } else if (this.isValidHostname(trimmed)) {
            isValid = true;
            message = '✓ Valid hostname';
        } else {
            message = '⚠ Invalid format. Use IP address or hostname.';
        }
        
        validationMsg.textContent = message;
        validationMsg.className = `validation-message ${isValid ? 'valid' : 'invalid'}`;
        targetInput.setAttribute('aria-invalid', !isValid);
    }

    /**
     * Start traceroute with enhanced error handling and feedback
     */
    async startTraceroute() {
        if (this.isRunning) {
            this.showToast('Traceroute already in progress...', 'warning');
            return;
        }

        const target = document.getElementById('target')?.value.trim();
        const maxHops = parseInt(document.getElementById('maxHops')?.value) || 30;
        const timeout = parseFloat(document.getElementById('timeout')?.value) || 5.0;

        if (!target) {
            this.showToast('Please enter a target host or IP address', 'error');
            return;
        }

        if (!this.isValidIP(target) && !this.isValidHostname(target)) {
            this.showToast('Please enter a valid IP address or hostname', 'error');
            return;
        }

        this.isRunning = true;
        this.updateStatus('running', 'Running traceroute...');
        this.showLoading('hops-container', 'Running traceroute...');

        try {
            // Simulate traceroute execution with progress updates
            await this.simulateTraceroute(target, maxHops, timeout);
            
            this.updateStatus('complete', 'Traceroute completed');
            this.showToast('Traceroute completed successfully', 'success');
            
        } catch (error) {
            this.updateStatus('error', 'Traceroute failed');
            this.showToast(`Traceroute failed: ${error.message}`, 'error');
            this.showError('hops-container', error.message);
        } finally {
            this.isRunning = false;
        }
    }

    /**
     * Simulate traceroute with progress updates
     */
    async simulateTraceroute(target, maxHops, timeout) {
        return new Promise((resolve, reject) => {
            let progress = 0;
            const progressInterval = setInterval(() => {
                progress += Math.random() * 20;
                if (progress >= 100) {
                    progress = 100;
                    clearInterval(progressInterval);
                    
                    // Use mock data for demonstration
                    this.currentResults = {
                        ...mockTracerouteData,
                        target: target,
                        target_ip: target.includes('.') ? target : '142.250.191.78',
                        max_hops: maxHops,
                        timeout: timeout
                    };

                    this.displayHops(this.currentResults);
                    this.displayRawData(this.currentResults);
                    resolve();
                }
                
                this.updateProgress(progress);
            }, 200);
        });
    }

    /**
     * Update progress indicator
     */
    updateProgress(percent) {
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        
        if (progressBar) {
            progressBar.style.width = `${percent}%`;
            progressBar.setAttribute('aria-valuenow', percent);
        }
        
        if (progressText) {
            progressText.textContent = `${Math.round(percent)}%`;
        }
    }

    /**
     * Update tool status
     */
    updateStatus(status, message) {
        const statusIndicator = document.querySelector('.status-indicator');
        const statusText = document.getElementById('statusText');
        
        if (statusIndicator) {
            statusIndicator.className = `status-indicator status-${status}`;
            statusIndicator.setAttribute('aria-label', `Status: ${message}`);
        }
        
        if (statusText) {
            statusText.textContent = message;
        }
    }

    /**
     * Show loading state with spinner
     */
    showLoading(containerId, message) {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        container.innerHTML = `
            <div class="loading-container" role="status" aria-live="polite">
                <div class="spinner" aria-hidden="true"></div>
                <p>${message}</p>
                <div class="progress-container">
                    <div class="progress-bar">
                        <div id="progressBar" class="progress-fill" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100"></div>
                    </div>
                    <span id="progressText">0%</span>
                </div>
            </div>
        `;
    }

    /**
     * Show error state
     */
    showError(containerId, message) {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        container.innerHTML = `
            <div class="error-container" role="alert">
                <div class="error-icon">⚠️</div>
                <h3>Error</h3>
                <p>${message}</p>
                <button onclick="tracerouteTool.retryTraceroute()" class="retry-btn">Retry</button>
            </div>
        `;
    }

    /**
     * Retry traceroute
     */
    retryTraceroute() {
        this.startTraceroute();
    }

    /**
     * Display traceroute hops with enhanced UI
     */
    displayHops(data) {
        const container = document.getElementById('hops-container');
        if (!container) return;
        
        if (!data || !data.hops) {
            container.innerHTML = '<div class="no-data"><p>No traceroute data available</p></div>';
            return;
        }

        let html = `
            <div class="analysis-section">
                <h3>📈 Traceroute Summary</h3>
                <div class="hop-details">
                    <div class="detail-item">
                        <div class="detail-label">Target:</div>
                        <div class="detail-value">${data.target} (${data.target_ip})</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Total Hops:</div>
                        <div class="detail-value">${data.total_hops}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Timestamp:</div>
                        <div class="detail-value">${new Date(data.timestamp).toLocaleString()}</div>
                    </div>
                </div>
            </div>
        `;

        data.hops.forEach((hop, index) => {
            const avgRtt = hop.rtt && hop.rtt.length > 0 ? 
                (hop.rtt.reduce((a, b) => a + b, 0) / hop.rtt.length).toFixed(1) : 'N/A';
            
            const statusClass = hop.ip ? 'status-success' : 'status-error';
            const statusText = hop.ip ? 'Reachable' : 'Unreachable';
            const isPrivate = this.isPrivateIP(hop.ip);
            const hasSecurityIssues = this.checkSecurityIssues(hop);

            html += `
                <div class="hop-item ${hasSecurityIssues ? 'security-warning' : ''}" data-hop="${hop.hop}">
                    <div class="hop-header">
                        <div class="hop-number">${hop.hop}</div>
                        <div class="hop-status ${statusClass}">
                            <span class="status-dot"></span>
                            ${statusText}
                        </div>
                    </div>
                    <div class="hop-content">
                        <div class="hop-info">
                            <div class="ip-info">
                                <strong>IP:</strong> ${hop.ip || 'N/A'}
                                ${isPrivate ? '<span class="private-badge">Private</span>' : ''}
                            </div>
                            <div class="hostname-info">
                                <strong>Hostname:</strong> ${hop.hostname || 'N/A'}
                            </div>
                            <div class="rtt-info">
                                <strong>RTT:</strong> ${avgRtt}ms
                                ${hop.rtt ? `<span class="rtt-details">(${hop.rtt.join(', ')}ms)</span>` : ''}
                            </div>
                        </div>
                        ${this.renderOSINTData(hop.osint_data)}
                        ${hasSecurityIssues ? this.renderSecurityWarnings(hop) : ''}
                    </div>
                </div>
            `;
        });

        container.innerHTML = html;
        
        // Add click handlers for expandable sections
        this.setupHopInteractions();
    }

    /**
     * Render OSINT data section
     */
    renderOSINTData(osintData) {
        if (!osintData) return '';
        
        return `
            <div class="osint-section">
                <h4>OSINT Data</h4>
                <div class="osint-grid">
                    ${osintData.whois?.organization ? `
                        <div class="osint-item">
                            <strong>Organization:</strong> ${osintData.whois.organization}
                        </div>
                    ` : ''}
                    ${osintData.geolocation?.country ? `
                        <div class="osint-item">
                            <strong>Location:</strong> ${osintData.geolocation.city || ''} ${osintData.geolocation.country}
                        </div>
                    ` : ''}
                    ${osintData.ports && osintData.ports.length > 0 ? `
                        <div class="osint-item">
                            <strong>Open Ports:</strong> ${osintData.ports.join(', ')}
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    /**
     * Render security warnings
     */
    renderSecurityWarnings(hop) {
        const warnings = [];
        
        if (this.isPrivateIP(hop.ip)) {
            warnings.push('Private IP in public route');
        }
        
        if (hop.osint_data?.ports?.includes(22)) {
            warnings.push('SSH port (22) open');
        }
        
        if (hop.osint_data?.ports?.includes(23)) {
            warnings.push('Telnet port (23) open');
        }
        
        if (warnings.length === 0) return '';
        
        return `
            <div class="security-warnings">
                <h4>⚠️ Security Concerns</h4>
                <ul>
                    ${warnings.map(warning => `<li>${warning}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    /**
     * Check for security issues in hop
     */
    checkSecurityIssues(hop) {
        return this.isPrivateIP(hop.ip) || 
               (hop.osint_data?.ports && 
                (hop.osint_data.ports.includes(22) || hop.osint_data.ports.includes(23)));
    }

    /**
     * Set up hop item interactions
     */
    setupHopInteractions() {
        document.querySelectorAll('.hop-item').forEach(hopItem => {
            hopItem.addEventListener('click', () => {
                hopItem.classList.toggle('expanded');
            });
        });
    }

    /**
     * Analyze traceroute results
     */
    analyzeResults() {
        if (!this.currentResults) {
            this.showToast('No traceroute data to analyze', 'warning');
            return;
        }

        const analysis = this.performAnalysis(this.currentResults);
        this.displayAnalysis(analysis);
        this.showTab('analysis');
        this.showToast('Analysis completed', 'success');
    }

    /**
     * Perform comprehensive analysis
     */
    performAnalysis(data) {
        const countries = new Set();
        const organizations = new Set();
        let privateIPs = 0;
        let publicIPs = 0;
        const securityConcerns = [];
        const recommendations = [];

        data.hops.forEach(hop => {
            if (hop.osint_data) {
                if (hop.osint_data.geolocation?.country) {
                    countries.add(hop.osint_data.geolocation.country);
                }
                if (hop.osint_data.whois?.organization) {
                    organizations.add(hop.osint_data.whois.organization);
                }
                if (this.isPrivateIP(hop.ip)) {
                    privateIPs++;
                    securityConcerns.push(`Private IP ${hop.ip} in public route`);
                } else {
                    publicIPs++;
                }
                
                // Check for open ports
                if (hop.osint_data.ports) {
                    hop.osint_data.ports.forEach(port => {
                        if (port === 22) {
                            securityConcerns.push(`Open SSH port on ${hop.ip}`);
                        } else if (port === 23) {
                            securityConcerns.push(`Open Telnet port on ${hop.ip}`);
                        }
                    });
                }
            }
        });

        // Generate recommendations
        if (privateIPs > 0) {
            recommendations.push('Review network segmentation for private IP exposure');
        }
        if (securityConcerns.some(c => c.includes('SSH'))) {
            recommendations.push('Consider restricting SSH access on public routers');
        }
        if (securityConcerns.some(c => c.includes('Telnet'))) {
            recommendations.push('Disable Telnet access - use SSH instead');
        }

        return {
            summary: {
                total_hops: data.hops.length,
                countries: Array.from(countries),
                organizations: Array.from(organizations),
                private_ips: privateIPs,
                public_ips: publicIPs
            },
            security_concerns: securityConcerns,
            recommendations: recommendations,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Display analysis results
     */
    displayAnalysis(analysis) {
        const container = document.getElementById('analysis-container');
        if (!container) return;

        container.innerHTML = `
            <div class="analysis-results">
                <h3>🔍 Analysis Results</h3>
                
                <div class="analysis-section">
                    <h4>Summary</h4>
                    <div class="summary-grid">
                        <div class="summary-item">
                            <strong>Total Hops:</strong> ${analysis.summary.total_hops}
                        </div>
                        <div class="summary-item">
                            <strong>Countries:</strong> ${analysis.summary.countries.join(', ') || 'Unknown'}
                        </div>
                        <div class="summary-item">
                            <strong>Organizations:</strong> ${analysis.summary.organizations.join(', ') || 'Unknown'}
                        </div>
                        <div class="summary-item">
                            <strong>Private IPs:</strong> ${analysis.summary.private_ips}
                        </div>
                        <div class="summary-item">
                            <strong>Public IPs:</strong> ${analysis.summary.public_ips}
                        </div>
                    </div>
                </div>

                ${analysis.security_concerns.length > 0 ? `
                    <div class="analysis-section security-section">
                        <h4>⚠️ Security Concerns</h4>
                        <ul class="security-list">
                            ${analysis.security_concerns.map(concern => `<li>${concern}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}

                ${analysis.recommendations.length > 0 ? `
                    <div class="analysis-section recommendations-section">
                        <h4>💡 Recommendations</h4>
                        <ul class="recommendations-list">
                            ${analysis.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        `;
    }

    /**
     * Display raw data
     */
    displayRawData(data) {
        const container = document.getElementById('raw-data-container');
        if (!container) return;

        container.innerHTML = `
            <div class="raw-data">
                <h3>📄 Raw Data</h3>
                <pre><code>${JSON.stringify(data, null, 2)}</code></pre>
            </div>
        `;
    }

    /**
     * Show specific tab
     */
    showTab(tabName) {
        // Hide all tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.style.display = 'none';
        });

        // Remove active class from all tabs
        document.querySelectorAll('[data-tab]').forEach(tab => {
            tab.classList.remove('active');
        });

        // Show selected tab content
        const targetContent = document.getElementById(`${tabName}-tab`);
        if (targetContent) {
            targetContent.style.display = 'block';
        }

        // Add active class to selected tab
        const targetTab = document.querySelector(`[data-tab="${tabName}"]`);
        if (targetTab) {
            targetTab.classList.add('active');
        }
    }

    /**
     * Load map view (placeholder for future implementation)
     */
    loadMapView() {
        const container = document.getElementById('map-container');
        if (!container) return;

        container.innerHTML = `
            <div class="map-placeholder">
                <h3>🗺️ Geographic Visualization</h3>
                <p>Map view will be implemented in a future update.</p>
                <p>This will show the geographic path of your traceroute.</p>
            </div>
        `;
    }

    /**
     * Clear all results
     */
    clearResults() {
        if (!confirm('Are you sure you want to clear all results?')) {
            return;
        }

        this.currentResults = null;
        this.analysisCache.clear();
        
        const containers = ['hops-container', 'analysis-container', 'raw-data-container'];
        containers.forEach(id => {
            const container = document.getElementById(id);
            if (container) {
                container.innerHTML = '';
            }
        });

        this.updateStatus('ready', 'Ready for new traceroute');
        this.showToast('Results cleared', 'info');
    }

    /**
     * Export results in various formats
     */
    exportResults(format = 'json') {
        if (!this.currentResults) {
            this.showToast('No results to export', 'warning');
            return;
        }

        try {
            let content, filename, mimeType;
            
            switch (format) {
                case 'json':
                    content = JSON.stringify(this.currentResults, null, 2);
                    filename = `traceroute-${this.currentResults.target}-${Date.now()}.json`;
                    mimeType = 'application/json';
                    break;
                    
                case 'csv':
                    content = this.convertToCSV(this.currentResults);
                    filename = `traceroute-${this.currentResults.target}-${Date.now()}.csv`;
                    mimeType = 'text/csv';
                    break;
                    
                case 'txt':
                    content = this.convertToTXT(this.currentResults);
                    filename = `traceroute-${this.currentResults.target}-${Date.now()}.txt`;
                    mimeType = 'text/plain';
                    break;
                    
                default:
                    throw new Error('Unsupported export format');
            }

            this.downloadFile(content, filename, mimeType);
            this.showToast(`Results exported as ${format.toUpperCase()}`, 'success');
            
            // Log export
            this.exportHistory.push({
                format,
                filename,
                timestamp: new Date().toISOString()
            });
            
        } catch (error) {
            this.showToast(`Export failed: ${error.message}`, 'error');
        }
    }

    /**
     * Convert results to CSV format
     */
    convertToCSV(data) {
        const headers = ['Hop', 'IP', 'Hostname', 'RTT (ms)', 'Organization', 'Country', 'Open Ports'];
        const rows = [headers.join(',')];
        
        data.hops.forEach(hop => {
            const avgRtt = hop.rtt && hop.rtt.length > 0 ? 
                (hop.rtt.reduce((a, b) => a + b, 0) / hop.rtt.length).toFixed(1) : 'N/A';
            
            const row = [
                hop.hop,
                hop.ip || 'N/A',
                hop.hostname || 'N/A',
                avgRtt,
                hop.osint_data?.whois?.organization || 'N/A',
                hop.osint_data?.geolocation?.country || 'N/A',
                hop.osint_data?.ports?.join(';') || 'N/A'
            ].map(field => `"${field}"`).join(',');
            
            rows.push(row);
        });
        
        return rows.join('\n');
    }

    /**
     * Convert results to TXT format
     */
    convertToTXT(data) {
        let content = `Traceroute Results for ${data.target}\n`;
        content += `Generated: ${new Date(data.timestamp).toLocaleString()}\n`;
        content += `Total Hops: ${data.total_hops}\n\n`;
        
        data.hops.forEach(hop => {
            const avgRtt = hop.rtt && hop.rtt.length > 0 ? 
                (hop.rtt.reduce((a, b) => a + b, 0) / hop.rtt.length).toFixed(1) : 'N/A';
            
            content += `Hop ${hop.hop}: ${hop.ip || 'N/A'} (${hop.hostname || 'N/A'})\n`;
            content += `  RTT: ${avgRtt}ms\n`;
            if (hop.osint_data?.whois?.organization) {
                content += `  Organization: ${hop.osint_data.whois.organization}\n`;
            }
            if (hop.osint_data?.geolocation?.country) {
                content += `  Location: ${hop.osint_data.geolocation.country}\n`;
            }
            if (hop.osint_data?.ports?.length > 0) {
                content += `  Open Ports: ${hop.osint_data.ports.join(', ')}\n`;
            }
            content += '\n';
        });
        
        return content;
    }

    /**
     * Copy results to clipboard
     */
    async copyToClipboard() {
        if (!this.currentResults) {
            this.showToast('No results to copy', 'warning');
            return;
        }

        try {
            const text = JSON.stringify(this.currentResults, null, 2);
            await navigator.clipboard.writeText(text);
            this.showToast('Results copied to clipboard', 'success');
        } catch (error) {
            this.showToast('Failed to copy to clipboard', 'error');
        }
    }

    /**
     * Download file
     */
    downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    /**
     * Show toast notification
     */
    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.setAttribute('role', 'status');
        toast.setAttribute('aria-live', 'polite');
        toast.textContent = message;
        
        document.body.appendChild(toast);
        
        // Animate in
        setTimeout(() => toast.classList.add('show'), 10);
        
        // Auto remove
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    /**
     * Validate IP address
     */
    isValidIP(ip) {
        if (!ip) return false;
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipRegex.test(ip);
    }

    /**
     * Validate hostname
     */
    isValidHostname(hostname) {
        if (!hostname) return false;
        const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
        return hostnameRegex.test(hostname);
    }

    /**
     * Check if IP is private
     */
    isPrivateIP(ip) {
        if (!ip) return false;
        const privateRanges = [
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
            /^192\.168\./
        ];
        return privateRanges.some(range => range.test(ip));
    }
}

// Mock data (existing)
const mockTracerouteData = {
    "target": "google.com",
    "target_ip": "142.250.191.78",
    "timestamp": new Date().toISOString(),
    "total_hops": 12,
    "hops": [
        {
            "hop": 1,
            "ip": "192.168.1.1",
            "hostname": "router.local",
            "rtt": [2.1, 1.8, 2.3],
            "osint_data": {
                "ip": "192.168.1.1",
                "reverse_dns": "router.local",
                "whois": {},
                "dns_records": {"PTR": "router.local"},
                "geolocation": {"error": "Private IP"},
                "ports": []
            }
        },
        {
            "hop": 2,
            "ip": "10.0.0.1",
            "hostname": "gateway.isp.com",
            "rtt": [15.2, 14.8, 15.5],
            "osint_data": {
                "ip": "10.0.0.1",
                "reverse_dns": "gateway.isp.com",
                "whois": {"organization": "ISP Network"},
                "dns_records": {"PTR": "gateway.isp.com"},
                "geolocation": {"error": "Private IP"},
                "ports": [80, 443]
            }
        },
        {
            "hop": 3,
            "ip": "203.0.113.1",
            "hostname": "core-router.isp.com",
            "rtt": [25.1, 24.9, 25.3],
            "osint_data": {
                "ip": "203.0.113.1",
                "reverse_dns": "core-router.isp.com",
                "whois": {"organization": "ISP Core Network"},
                "dns_records": {"PTR": "core-router.isp.com"},
                "geolocation": {"country": "Australia", "city": "Sydney"},
                "ports": [22, 80, 443]
            }
        },
        {
            "hop": 4,
            "ip": "8.8.8.8",
            "hostname": "dns.google",
            "rtt": [35.2, 35.0, 35.4],
            "osint_data": {
                "ip": "8.8.8.8",
                "reverse_dns": "dns.google",
                "whois": {"organization": "Google LLC"},
                "dns_records": {"PTR": "dns.google"},
                "geolocation": {"country": "United States", "city": "Mountain View"},
                "ports": [53, 443]
            }
        },
        {
            "hop": 5,
            "ip": "142.250.191.78",
            "hostname": "syd15s01-in-f14.1e100.net",
            "rtt": [45.1, 44.8, 45.3],
            "osint_data": {
                "ip": "142.250.191.78",
                "reverse_dns": "syd15s01-in-f14.1e100.net",
                "whois": {"organization": "Google LLC"},
                "dns_records": {"PTR": "syd15s01-in-f14.1e100.net"},
                "geolocation": {"country": "Australia", "city": "Sydney"},
                "ports": [80, 443, 8080]
            }
        }
    ]
};

// Initialize the tool
const tracerouteTool = new TracerouteOSINTTool();

// Legacy function compatibility
function startTraceroute() { tracerouteTool.startTraceroute(); }
function analyzeResults() { tracerouteTool.analyzeResults(); }
function clearResults() { tracerouteTool.clearResults(); }
function exportResults() { tracerouteTool.exportResults(); }
function showTab(tabName) { tracerouteTool.showTab(tabName); }
function loadMapView() { tracerouteTool.loadMapView(); }
function copyToClipboard() { tracerouteTool.copyToClipboard(); }
function isValidIP(ip) { return tracerouteTool.isValidIP(ip); }
function isValidHostname(hostname) { return tracerouteTool.isValidHostname(hostname); } 