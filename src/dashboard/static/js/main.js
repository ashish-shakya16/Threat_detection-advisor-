// Main Dashboard JavaScript
// Real-time threat monitoring and system metrics

// Initialize Socket.IO connection
const socket = io();

// Global state
let timelineChart = null;
let distributionChart = null;
let monitoringActive = false;

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', () => {
    console.log('Dashboard initializing...');
    
    // Initialize charts
    initializeCharts();
    
    // Load initial data
    loadStats();
    loadRecentThreats();
    loadSystemMetrics();
    loadThreatTimeline();
    
    // Set up event listeners
    setupEventListeners();
    
    // Start auto-refresh
    setInterval(loadStats, 5000);
    setInterval(loadSystemMetrics, 2000);
    
    console.log('Dashboard initialized');
});

// ==================== EVENT LISTENERS ====================

function setupEventListeners() {
    // Scan button
    document.getElementById('scanBtn').addEventListener('click', runScan);
    
    // Monitor button
    document.getElementById('monitorBtn').addEventListener('click', toggleMonitoring);
    
    // Time filter buttons
    document.querySelectorAll('.time-filter button').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.time-filter button').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            const hours = parseInt(e.target.dataset.hours);
            loadThreatTimeline(hours);
        });
    });
}

// ==================== SOCKET.IO EVENTS ====================

socket.on('connect', () => {
    console.log('Connected to server');
    updateConnectionStatus(true);
});

socket.on('disconnect', () => {
    console.log('Disconnected from server');
    updateConnectionStatus(false);
});

socket.on('new_threats', (data) => {
    console.log('New threats received:', data);
    showNotification('warning', `${data.count} new threat(s) detected!`);
    loadStats();
    loadRecentThreats();
    loadThreatTimeline();
});

socket.on('system_metrics', (data) => {
    updateSystemMetricsUI(data);
});

// ==================== API CALLS ====================

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const result = await response.json();
        
        if (result.success) {
            updateStatsUI(result.data);
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

async function loadRecentThreats() {
    try {
        const response = await fetch('/api/threats?limit=10');
        const result = await response.json();
        
        if (result.success) {
            updateThreatsTable(result.data);
        }
    } catch (error) {
        console.error('Error loading threats:', error);
    }
}

async function loadSystemMetrics() {
    try {
        const response = await fetch('/api/system-metrics');
        const result = await response.json();
        
        if (result.success) {
            updateSystemMetricsUI(result.data);
        }
    } catch (error) {
        console.error('Error loading metrics:', error);
    }
}

async function loadThreatTimeline(hours = 24) {
    try {
        const response = await fetch(`/api/threat-timeline?hours=${hours}`);
        const result = await response.json();
        
        if (result.success) {
            updateTimelineChart(result.data);
        }
    } catch (error) {
        console.error('Error loading timeline:', error);
    }
}

async function runScan() {
    const btn = document.getElementById('scanBtn');
    const icon = btn.querySelector('i');
    
    btn.disabled = true;
    icon.classList.add('fa-spin');
    showNotification('info', 'Scan started...');
    
    try {
        const response = await fetch('/api/scan/start', { method: 'POST' });
        const result = await response.json();
        
        if (result.success) {
            showNotification('success', result.message);
            loadStats();
            loadRecentThreats();
            loadThreatTimeline();
        } else {
            showNotification('error', result.error || 'Scan failed');
        }
    } catch (error) {
        showNotification('error', 'Scan error: ' + error.message);
    } finally {
        btn.disabled = false;
        icon.classList.remove('fa-spin');
    }
}

async function toggleMonitoring() {
    const btn = document.getElementById('monitorBtn');
    const isActive = btn.dataset.monitoring === 'true';
    
    try {
        const endpoint = isActive ? '/api/monitoring/stop' : '/api/monitoring/start';
        const response = await fetch(endpoint, { method: 'POST' });
        const result = await response.json();
        
        if (result.success) {
            monitoringActive = !isActive;
            btn.dataset.monitoring = monitoringActive.toString();
            
            if (monitoringActive) {
                btn.classList.add('active');
                btn.innerHTML = '<i class="fas fa-stop"></i><span>Stop Monitoring</span>';
                showNotification('success', 'Continuous monitoring started');
            } else {
                btn.classList.remove('active');
                btn.innerHTML = '<i class="fas fa-play"></i><span>Start Monitoring</span>';
                showNotification('info', 'Monitoring stopped');
            }
        }
    } catch (error) {
        showNotification('error', 'Error toggling monitoring: ' + error.message);
    }
}

// ==================== UI UPDATES ====================

function updateStatsUI(stats) {
    const severity = stats.by_severity || {};
    
    document.getElementById('criticalCount').textContent = severity.critical || 0;
    document.getElementById('highCount').textContent = severity.high || 0;
    document.getElementById('mediumCount').textContent = severity.medium || 0;
    document.getElementById('lowCount').textContent = severity.low || 0;
    
    // Update distribution chart
    if (distributionChart) {
        const severityData = [
            severity.critical || 0,
            severity.high || 0,
            severity.medium || 0,
            severity.low || 0
        ];
        distributionChart.data.datasets[0].data = severityData;
        distributionChart.update();
    }
}

function updateSystemMetricsUI(metrics) {
    document.getElementById('cpuValue').textContent = metrics.cpu_percent.toFixed(1) + '%';
    document.getElementById('cpuBar').style.width = metrics.cpu_percent + '%';
    
    document.getElementById('memoryValue').textContent = metrics.memory_percent.toFixed(1) + '%';
    document.getElementById('memoryBar').style.width = metrics.memory_percent + '%';
    
    document.getElementById('networkValue').textContent = metrics.network_connections;
    document.getElementById('processValue').textContent = metrics.process_count;
}

function updateThreatsTable(threats) {
    const tbody = document.getElementById('threatsTableBody');
    
    if (!threats || threats.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="no-data">
                    <i class="fas fa-shield-alt"></i>
                    <p>No threats detected. System is secure.</p>
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = threats.map(threat => {
        const time = formatTimestamp(threat.timestamp);
        const severityClass = threat.severity.toLowerCase();
        
        return `
            <tr>
                <td>
                    <span class="severity-badge ${severityClass}">
                        ${threat.severity}
                    </span>
                </td>
                <td>${threat.threat_name || 'Unknown'}</td>
                <td>${threat.category || 'Unknown'}</td>
                <td>${(threat.risk_score || 0).toFixed(2)}</td>
                <td>${time}</td>
                <td>
                    <button class="btn-secondary" style="padding: 0.25rem 0.75rem; font-size: 0.875rem;">
                        View Details
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function updateConnectionStatus(connected) {
    const indicator = document.getElementById('connectionStatus');
    const text = document.getElementById('connectionText');
    
    if (connected) {
        indicator.classList.add('connected');
        indicator.classList.remove('disconnected');
        text.textContent = 'Connected';
    } else {
        indicator.classList.add('disconnected');
        indicator.classList.remove('connected');
        text.textContent = 'Disconnected';
    }
}

// ==================== CHARTS ====================

function initializeCharts() {
    // Timeline Chart
    const timelineCtx = document.getElementById('timelineChart').getContext('2d');
    timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Critical',
                    data: [],
                    borderColor: '#dc2626',
                    backgroundColor: 'rgba(220, 38, 38, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'High',
                    data: [],
                    borderColor: '#ea580c',
                    backgroundColor: 'rgba(234, 88, 12, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Medium',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Low',
                    data: [],
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#94a3b8' }
                }
            },
            scales: {
                x: { 
                    ticks: { color: '#94a3b8' },
                    grid: { color: '#334155' }
                },
                y: { 
                    ticks: { color: '#94a3b8' },
                    grid: { color: '#334155' }
                }
            }
        }
    });
    
    // Distribution Chart
    const distCtx = document.getElementById('distributionChart').getContext('2d');
    distributionChart = new Chart(distCtx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#dc2626', '#ea580c', '#f59e0b', '#3b82f6']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8' }
                }
            }
        }
    });
}

function updateTimelineChart(data) {
    if (!timelineChart || !data || data.length === 0) return;
    
    const labels = data.map(d => {
        const date = new Date(d.time);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });
    
    const criticalData = data.map(d => d.critical || 0);
    const highData = data.map(d => d.high || 0);
    const mediumData = data.map(d => d.medium || 0);
    const lowData = data.map(d => d.low || 0);
    
    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = criticalData;
    timelineChart.data.datasets[1].data = highData;
    timelineChart.data.datasets[2].data = mediumData;
    timelineChart.data.datasets[3].data = lowData;
    timelineChart.update();
}

// ==================== NOTIFICATIONS ====================

function showNotification(type, message) {
    const container = document.getElementById('notificationContainer');
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <div style="display: flex; align-items: center; gap: 0.5rem;">
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
            <span>${message}</span>
        </div>
    `;
    
    container.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}
