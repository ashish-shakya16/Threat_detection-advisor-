// Analytics Page JavaScript

const socket = io();

let trendChart = null;
let categoryChart = null;
let riskChart = null;

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', () => {
    initializeCharts();
    loadAnalyticsData();
    setupEventListeners();
});

// ==================== SOCKET.IO ====================

socket.on('connect', () => {
    updateConnectionStatus(true);
});

socket.on('disconnect', () => {
    updateConnectionStatus(false);
});

socket.on('new_threats', () => {
    loadAnalyticsData();
});

// ==================== EVENT LISTENERS ====================

function setupEventListeners() {
    document.querySelectorAll('.time-filter button').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.time-filter button').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            const period = e.target.dataset.period;
            loadAnalyticsData(period);
        });
    });
}

// ==================== API CALLS ====================

async function loadAnalyticsData(period = '24h') {
    const hours = period === '24h' ? 24 : period === '7d' ? 168 : 720;
    
    try {
        // Load stats
        const statsResponse = await fetch('/api/stats');
        const statsResult = await statsResponse.json();
        
        // Load timeline
        const timelineResponse = await fetch(`/api/threat-timeline?hours=${hours}`);
        const timelineResult = await timelineResponse.json();
        
        // Load threats for category analysis
        const threatsResponse = await fetch(`/api/threats?limit=1000&hours=${hours}`);
        const threatsResult = await threatsResponse.json();
        
        if (statsResult.success) {
            updateStatsUI(statsResult.data, threatsResult.data);
        }
        
        if (timelineResult.success) {
            updateTrendChart(timelineResult.data);
        }
        
        if (threatsResult.success) {
            updateCategoryChart(threatsResult.data);
            updateRiskChart(threatsResult.data);
        }
    } catch (error) {
        console.error('Error loading analytics:', error);
    }
}

// ==================== CHARTS ====================

function initializeCharts() {
    // Trend Chart
    const trendCtx = document.getElementById('trendChart').getContext('2d');
    trendChart = new Chart(trendCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Threats',
                data: [],
                borderColor: '#4f46e5',
                backgroundColor: 'rgba(79, 70, 229, 0.1)',
                tension: 0.4,
                fill: true
            }]
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
                    grid: { color: '#334155' },
                    beginAtZero: true
                }
            }
        }
    });
    
    // Category Chart
    const categoryCtx = document.getElementById('categoryChart').getContext('2d');
    categoryChart = new Chart(categoryCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Threats by Category',
                data: [],
                backgroundColor: [
                    '#dc2626',
                    '#ea580c',
                    '#f59e0b',
                    '#3b82f6',
                    '#06b6d4',
                    '#10b981'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: { 
                    ticks: { color: '#94a3b8' },
                    grid: { display: false }
                },
                y: { 
                    ticks: { color: '#94a3b8' },
                    grid: { color: '#334155' },
                    beginAtZero: true
                }
            }
        }
    });
    
    // Risk Chart
    const riskCtx = document.getElementById('riskChart').getContext('2d');
    riskChart = new Chart(riskCtx, {
        type: 'pie',
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

function updateTrendChart(data) {
    if (!trendChart || !data || data.length === 0) return;
    
    const labels = data.map(d => {
        const date = new Date(d.time);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });
    
    const counts = data.map(d => d.count);
    
    trendChart.data.labels = labels;
    trendChart.data.datasets[0].data = counts;
    trendChart.update();
}

function updateCategoryChart(threats) {
    if (!categoryChart || !threats) return;
    
    // Count threats by category
    const categories = {};
    threats.forEach(threat => {
        const category = threat.category || 'Unknown';
        categories[category] = (categories[category] || 0) + 1;
    });
    
    const labels = Object.keys(categories);
    const data = Object.values(categories);
    
    categoryChart.data.labels = labels;
    categoryChart.data.datasets[0].data = data;
    categoryChart.update();
}

function updateRiskChart(threats) {
    if (!riskChart || !threats) return;
    
    // Count by severity
    const severity = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
    };
    
    threats.forEach(threat => {
        const sev = threat.severity.toLowerCase();
        if (severity.hasOwnProperty(sev)) {
            severity[sev]++;
        }
    });
    
    riskChart.data.datasets[0].data = [
        severity.critical,
        severity.high,
        severity.medium,
        severity.low
    ];
    riskChart.update();
}

// ==================== UI UPDATES ====================

function updateStatsUI(stats, threats) {
    const total = stats.total || 0;
    document.getElementById('totalThreats').textContent = total;
    
    if (threats && threats.length > 0) {
        // Calculate average risk score
        const avgRisk = threats.reduce((sum, t) => sum + (t.risk_score || 0), 0) / threats.length;
        document.getElementById('avgRisk').textContent = avgRisk.toFixed(2);
        
        // Find most common category
        const categories = {};
        threats.forEach(t => {
            const cat = t.category || 'Unknown';
            categories[cat] = (categories[cat] || 0) + 1;
        });
        
        const mostCommon = Object.entries(categories).sort((a, b) => b[1] - a[1])[0];
        if (mostCommon) {
            document.getElementById('mostCommon').textContent = mostCommon[0];
        }
    } else {
        document.getElementById('avgRisk').textContent = '0.00';
        document.getElementById('mostCommon').textContent = '-';
    }
    
    document.getElementById('detectionRate').textContent = '100%';
}

// ==================== CONNECTION STATUS ====================

function updateConnectionStatus(connected) {
    const status = document.getElementById('connectionStatus');
    const text = document.getElementById('connectionText');
    
    if (connected) {
        status.className = 'status-indicator connected';
        text.textContent = 'Connected';
    } else {
        status.className = 'status-indicator disconnected';
        text.textContent = 'Disconnected';
    }
}
