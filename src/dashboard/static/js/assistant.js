// AI Assistant Page JavaScript

const socket = io();

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', () => {
    const chatInput = document.getElementById('chatInput');
    
    // Auto-resize textarea
    chatInput.addEventListener('input', function() {
        this.style.height = 'auto';
        this.style.height = Math.min(this.scrollHeight, 120) + 'px';
    });
});

// ==================== SOCKET.IO ====================

socket.on('connect', () => {
    updateConnectionStatus(true);
});

socket.on('disconnect', () => {
    updateConnectionStatus(false);
});

// ==================== MESSAGE HANDLING ====================

function handleKeyPress(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
    }
}

async function sendMessage() {
    const input = document.getElementById('chatInput');
    const message = input.value.trim();
    
    if (!message) return;
    
    // Clear input
    input.value = '';
    input.style.height = 'auto';
    
    // Add user message to chat
    addMessage(message, 'user');
    
    // Show typing indicator
    showTypingIndicator();
    
    try {
        // Send to AI backend
        const response = await fetch('/api/assistant/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message: message })
        });
        
        const result = await response.json();
        
        // Remove typing indicator
        removeTypingIndicator();
        
        if (result.success) {
            addMessage(result.response, 'assistant');
        } else {
            addMessage('Sorry, I encountered an error. Please try again.', 'assistant');
        }
    } catch (error) {
        console.error('Error sending message:', error);
        removeTypingIndicator();
        addMessage('Sorry, I could not process your request. Please check your connection.', 'assistant');
    }
}

function askQuestion(question) {
    const input = document.getElementById('chatInput');
    input.value = question;
    sendMessage();
}

function addMessage(text, type) {
    const messagesContainer = document.getElementById('chatMessages');
    
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}-message`;
    
    if (type === 'assistant') {
        messageDiv.innerHTML = `
            <div class="message-avatar">
                <i class="fas fa-robot"></i>
            </div>
            <div class="message-content">
                <div class="message-text">${formatMessage(text)}</div>
                <div class="message-time">${new Date().toLocaleTimeString()}</div>
            </div>
        `;
    } else {
        messageDiv.innerHTML = `
            <div class="message-content">
                <div class="message-text">${escapeHtml(text)}</div>
                <div class="message-time">${new Date().toLocaleTimeString()}</div>
            </div>
            <div class="message-avatar">
                <i class="fas fa-user"></i>
            </div>
        `;
    }
    
    messagesContainer.appendChild(messageDiv);
    scrollToBottom();
}

function showTypingIndicator() {
    const messagesContainer = document.getElementById('chatMessages');
    
    const typingDiv = document.createElement('div');
    typingDiv.className = 'message assistant-message typing-indicator';
    typingDiv.id = 'typingIndicator';
    typingDiv.innerHTML = `
        <div class="message-avatar">
            <i class="fas fa-robot"></i>
        </div>
        <div class="message-content">
            <div class="typing-dots">
                <span></span>
                <span></span>
                <span></span>
            </div>
        </div>
    `;
    
    messagesContainer.appendChild(typingDiv);
    scrollToBottom();
}

function removeTypingIndicator() {
    const indicator = document.getElementById('typingIndicator');
    if (indicator) {
        indicator.remove();
    }
}

function clearChat() {
    if (confirm('Are you sure you want to clear the chat history?')) {
        const messagesContainer = document.getElementById('chatMessages');
        messagesContainer.innerHTML = `
            <div class="message assistant-message">
                <div class="message-avatar">
                    <i class="fas fa-robot"></i>
                </div>
                <div class="message-content">
                    <div class="message-text">
                        Chat cleared. How can I help you today?
                    </div>
                </div>
            </div>
        `;
    }
}

function scrollToBottom() {
    const messagesContainer = document.getElementById('chatMessages');
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function formatMessage(text) {
    // Convert markdown-like formatting
    let formatted = escapeHtml(text);
    
    // Bold text
    formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    
    // Code blocks
    formatted = formatted.replace(/`(.*?)`/g, '<code>$1</code>');
    
    // Line breaks
    formatted = formatted.replace(/\n/g, '<br>');
    
    // Lists
    formatted = formatted.replace(/^- (.*?)$/gm, '<li>$1</li>');
    if (formatted.includes('<li>')) {
        formatted = formatted.replace(/(<li>.*<\/li>)/s, '<ul style="margin: 0.5rem 0 0 1.5rem;">$1</ul>');
    }
    
    return formatted;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
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
