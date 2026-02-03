// Threats Page JavaScript

const socket = io();

let allThreats = [];
let filteredThreats = [];
let currentFilter = 'all';

// ==================== HELPER FUNCTIONS ====================

function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    // Format: Feb 2, 2026, 4:05:32 PM
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
    });
}

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', () => {
    loadThreats();
    setupEventListeners();
    
    // Auto-refresh every 10 seconds
    setInterval(loadThreats, 10000);
});

// ==================== EVENT LISTENERS ====================

function setupEventListeners() {
    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            currentFilter = e.target.dataset.filter;
            filterThreats();
        });
    });
    
    // Time filter
    document.getElementById('timeFilter').addEventListener('change', (e) => {
        loadThreats(parseInt(e.target.value));
    });
    
    // Search
    document.getElementById('searchInput').addEventListener('input', (e) => {
        searchThreats(e.target.value);
    });
}

// ==================== SOCKET.IO ====================

socket.on('connect', () => {
    updateConnectionStatus(true);
});

socket.on('disconnect', () => {
    updateConnectionStatus(false);
});

socket.on('new_threats', () => {
    loadThreats();
});

// ==================== API CALLS ====================

async function loadThreats(hours = 24) {
    try {
        const response = await fetch(`/api/threats?limit=100&hours=${hours}`);
        const result = await response.json();
        
        if (result.success) {
            allThreats = result.data;
            filteredThreats = [...allThreats];
            filterThreats();
        }
    } catch (error) {
        console.error('Error loading threats:', error);
    }
}

// ==================== FILTERING ====================

function filterThreats() {
    if (currentFilter === 'all') {
        filteredThreats = [...allThreats];
    } else {
        filteredThreats = allThreats.filter(threat => 
            threat.severity.toLowerCase() === currentFilter
        );
    }
    renderThreats();
}

function searchThreats(query) {
    if (!query) {
        filteredThreats = [...allThreats];
    } else {
        const lowerQuery = query.toLowerCase();
        filteredThreats = allThreats.filter(threat =>
            threat.threat_name.toLowerCase().includes(lowerQuery) ||
            threat.category.toLowerCase().includes(lowerQuery)
        );
    }
    renderThreats();
}

// ==================== RENDERING ====================

function renderThreats() {
    const container = document.getElementById('threatsListContent');
    
    if (!filteredThreats || filteredThreats.length === 0) {
        container.innerHTML = `
            <div style="text-align: center; padding: 3rem; color: var(--text-secondary);">
                <i class="fas fa-shield-alt" style="font-size: 4rem; margin-bottom: 1rem; opacity: 0.3;"></i>
                <p>No threats found matching your criteria.</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = filteredThreats.map(threat => {
        const time = formatTimestamp(threat.timestamp);
        const severityClass = threat.severity.toLowerCase();
        const details = threat.details ? JSON.parse(threat.details) : {};
        
        return `
            <div class="threat-card" data-severity="${severityClass}">
                <div class="threat-header">
                    <div>
                        <span class="severity-badge ${severityClass}">${threat.severity}</span>
                        <h3>${threat.threat_name || 'Unknown Threat'}</h3>
                    </div>
                    <button class="btn-secondary" onclick="viewThreatDetails(${threat.id})">
                        <i class="fas fa-info-circle"></i> Details
                    </button>
                </div>
                <div class="threat-info">
                    <div class="info-row">
                        <span class="label">Category:</span>
                        <span>${threat.category || 'Unknown'}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">Risk Score:</span>
                        <span class="risk-score">${(threat.risk_score || 0).toFixed(2)}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">Risk Level:</span>
                        <span>${threat.risk_level || 'Unknown'}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">Detected:</span>
                        <span>${time}</span>
                    </div>
                    ${details.process_name ? `
                    <div class="info-row">
                        <span class="label">Process:</span>
                        <span>${details.process_name}</span>
                    </div>
                    ` : ''}
                </div>
                <div class="threat-description">
                    ${threat.description || 'No description available.'}
                </div>
            </div>
        `;
    }).join('');
}

window.viewThreatDetails = async function(threatId) {
    try {
        const response = await fetch(`/api/threat/${threatId}`);
        const result = await response.json();
        
        if (result.success) {
            showThreatModal(result.data);
        } else {
            console.error('Error loading threat:', result.error);
            alert('Failed to load threat details: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error loading threat details:', error);
        alert('Failed to load threat details. Please try again.');
    }
}

function showThreatModal(threat) {
    const modal = document.getElementById('threatModal');
    const body = document.getElementById('threatModalBody');
    
    const details = threat.details ? JSON.parse(threat.details) : {};
    const time = formatTimestamp(threat.timestamp);
    const advisory = threat.advisory || {};
    
    // Generate simple advisory based on severity
    let advisoryNote = '';
    switch(threat.severity.toLowerCase()) {
        case 'critical':
            advisoryNote = '⚠️ Immediate action required. This threat poses a severe risk to system security and should be addressed urgently.';
            break;
        case 'high':
            advisoryNote = '🔴 High priority threat detected. Review and remediate as soon as possible to prevent potential security breaches.';
            break;
        case 'medium':
            advisoryNote = '🟡 Moderate risk identified. Monitor this threat and plan remediation within your security maintenance cycle.';
            break;
        case 'low':
            advisoryNote = '🟢 Low severity threat. Document and address during routine security maintenance procedures.';
            break;
    }
    
    body.innerHTML = `
        <div class="threat-detail">
            <div class="detail-header">
                <span class="severity-badge ${threat.severity.toLowerCase()}">${threat.severity}</span>
                <h2>${threat.threat_name}</h2>
            </div>
            
            <div class="detail-section">
                <h4>Security Advisory</h4>
                <div class="advisory-note">
                    ${advisoryNote}
                </div>
            </div>
            
            <div class="detail-section">
                <h4>Overview</h4>
                <div class="detail-grid">
                    <div><strong>ID:</strong> ${threat.threat_id}</div>
                    <div><strong>Category:</strong> ${threat.category}</div>
                    <div><strong>Risk Score:</strong> ${threat.risk_score.toFixed(2)}</div>
                    <div><strong>Confidence:</strong> ${(threat.confidence * 100).toFixed(0)}%</div>
                    <div><strong>Detected:</strong> ${time}</div>
                    <div><strong>Source:</strong> ${threat.source}</div>
                </div>
            </div>
            
            <div class="detail-section">
                <h4>Description</h4>
                <p>${threat.description}</p>
            </div>
            
            ${advisory.summary ? `
            <div class="detail-section">
                <h4>🛡️ Security Advisory</h4>
                <div class="advisory-box">
                    <p><strong>Summary:</strong> ${advisory.summary}</p>
                    ${advisory.explanation ? `<p><strong>Explanation:</strong> ${advisory.explanation}</p>` : ''}
                </div>
            </div>
            ` : ''}
            
            ${advisory.recommendations ? `
            <div class="detail-section">
                <h4>💡 Recommendations</h4>
                <div class="recommendations-box">
                    <p>${advisory.recommendations}</p>
                </div>
            </div>
            ` : ''}
            
            ${advisory.remediation_steps ? `
            <div class="detail-section">
                <h4>🔧 Remediation Steps</h4>
                <div class="remediation-box">
                    <pre>${advisory.remediation_steps}</pre>
                </div>
            </div>
            ` : ''}
            
            ${advisory.reference_links ? `
            <div class="detail-section">
                <h4>🔗 Reference Links</h4>
                <div class="links-box">
                    <p>${advisory.reference_links}</p>
                </div>
            </div>
            ` : ''}
            
            ${Object.keys(details).length > 0 ? `
            <div class="detail-section">
                <h4>Technical Details</h4>
                <pre>${JSON.stringify(details, null, 2)}</pre>
            </div>
            ` : ''}
        </div>
    `;
    
    modal.classList.add('active');
}

window.closeModal = function() {
    document.getElementById('threatModal').classList.remove('active');
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

// Add CSS for threat cards
const style = document.createElement('style');
style.textContent = `
    .threat-card {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 0.75rem;
        padding: 1.5rem;
        margin-bottom: 1rem;
        box-shadow: var(--shadow-md);
        transition: all 0.3s ease;
    }
    
    .threat-card:hover {
        transform: translateY(-2px);
        box-shadow: var(--shadow-lg);
    }
    
    .threat-header {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        margin-bottom: 1rem;
    }
    
    .threat-header h3 {
        margin-top: 0.5rem;
        font-size: 1.25rem;
    }
    
    .threat-info {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 0.75rem;
        margin-bottom: 1rem;
        padding: 1rem;
        background: var(--bg-tertiary);
        border-radius: 0.5rem;
    }
    
    .info-row {
        display: flex;
        gap: 0.5rem;
    }
    
    .info-row .label {
        color: var(--text-secondary);
        font-weight: 600;
    }
    
    .threat-description {
        color: var(--text-secondary);
        line-height: 1.6;
    }
    
    .detail-section {
        margin-bottom: 1.5rem;
    }
    
    .detail-section h4 {
        margin-bottom: 0.75rem;
        color: var(--accent-primary);
    }
    
    .detail-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 0.75rem;
        padding: 1rem;
        background: var(--bg-tertiary);
        border-radius: 0.5rem;
    }
    
    pre {
        background: var(--bg-tertiary);
        padding: 1rem;
        border-radius: 0.5rem;
        overflow-x: auto;
        color: var(--text-primary);
    }
`;
document.head.appendChild(style);
