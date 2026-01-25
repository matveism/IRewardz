/**
 * CONFIGURATION FILE - KEEP PRIVATE
 * This file contains sensitive information and API keys
 * NEVER commit this file to public repositories
 * Add to .gitignore: config.js
 */

const CONFIG = {
    // Google Apps Script URL
    APPS_SCRIPT_URL: 'https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec',
    
    // API Keys (Encrypted in production)
    API_KEYS: {
        WANNADS: '69745f8e8f2ce697824072',
        ADGEM: 'YOUR_ADGEM_API_KEY',
        OFFERTORO: 'YOUR_OFFERTORO_API_KEY',
        PERSONA: 'YOUR_PERSONALYZE_API_KEY'
    },
    
    // Security Settings
    SECURITY: {
        SESSION_TIMEOUT: 3600, // 1 hour in seconds
        MAX_LOGIN_ATTEMPTS: 5,
        PASSWORD_MIN_LENGTH: 8,
        ENABLE_2FA: true,
        ALLOWED_ORIGINS: ['https://yourdomain.com']
    },
    
    // Application Settings
    APP: {
        NAME: 'iRewardz',
        VERSION: '2.0.1',
        ENVIRONMENT: 'production', // development, staging, production
        MAINTENANCE_MODE: false,
        SUPPORT_EMAIL: 'support@irewardz.com',
        ADMIN_EMAIL: 'admin@irewardz.com'
    },
    
    // Points System
    POINTS: {
        HOLD_THRESHOLD: 4000,
        MIN_WITHDRAWAL: 1000,
        REFERRAL_BONUS: 250,
        WELCOME_BONUS: 500
    },
    
    // Database Configuration
    DATABASE: {
        VERSION: 1,
        TABLES: [
            'users',
            'transactions',
            'offerwalls',
            'cashout_options',
            'bonus_codes',
            'chat_messages',
            'leaderboard'
        ]
    },
    
    // Feature Flags
    FEATURES: {
        ENABLE_CHAT: true,
        ENABLE_REFERRALS: true,
        ENABLE_BONUS_CODES: true,
        ENABLE_LEADERBOARD: true,
        ENABLE_REAL_TIME_UPDATES: true
    }
};

// Encryption helper (simplified version)
class Security {
    static encrypt(data) {
        // In production, use proper encryption like AES-256
        // This is a simplified example
        try {
            return btoa(JSON.stringify(data));
        } catch (e) {
            console.error('Encryption error:', e);
            return null;
        }
    }

    static decrypt(encrypted) {
        try {
            return JSON.parse(atob(encrypted));
        } catch (e) {
            console.error('Decryption error:', e);
            return null;
        }
    }
    
    static hashPassword(password) {
        // In production, use bcrypt or similar
        // This is a simplified example
        let hash = 0;
        for (let i = 0; i < password.length; i++) {
            const char = password.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString();
    }
    
    static validateToken(token) {
        // Token validation logic
        return token && token.length > 20;
    }
    
    static sanitizeInput(input) {
        if (typeof input !== 'string') return input;
        return input
            .replace(/[<>]/g, '')
            .trim()
            .substring(0, 1000);
    }
}

// API Call Wrapper with Security
class APIService {
    constructor() {
        this.baseUrl = CONFIG.APPS_SCRIPT_URL;
        this.sessionId = this.getSessionId();
    }
    
    getSessionId() {
        return localStorage.getItem('session_id') || this.generateSessionId();
    }
    
    generateSessionId() {
        const id = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem('session_id', id);
        return id;
    }
    
    async call(endpoint, data = {}, method = 'POST') {
        const payload = {
            action: endpoint,
            session_id: this.sessionId,
            timestamp: Date.now(),
            data: Security.encrypt(data)
        };
        
        try {
            const response = await fetch(this.baseUrl, {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify(payload)
            });
            
            const result = await response.json();
            
            if (result.success) {
                return Security.decrypt(result.data) || result;
            } else {
                throw new Error(result.message || 'API call failed');
            }
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }
    
    // Auth endpoints
    async login(email, password) {
        return this.call('login', { 
            email, 
            password_hash: Security.hashPassword(password) 
        });
    }
    
    async signup(userData) {
        return this.call('signup', {
            ...userData,
            password_hash: Security.hashPassword(userData.password)
        });
    }
    
    async logout() {
        const result = await this.call('logout', {});
        localStorage.removeItem('session_id');
        return result;
    }
    
    // Data endpoints
    async getUserData() {
        return this.call('getUserData', {});
    }
    
    async getOfferwalls() {
        return this.call('getOfferwalls', {});
    }
    
    async getTransactions(limit = 50) {
        return this.call('getTransactions', { limit });
    }
    
    async redeemBonusCode(code) {
        return this.call('redeemBonus', { code: Security.sanitizeInput(code) });
    }
    
    async requestCashout(optionId) {
        return this.call('cashout', { optionId });
    }
    
    async sendChatMessage(message) {
        return this.call('sendChat', { 
            message: Security.sanitizeInput(message) 
        });
    }
}

// Global API instance
const API = new APIService();

// Session Management
class SessionManager {
    constructor() {
        this.sessionTimeout = CONFIG.SECURITY.SESSION_TIMEOUT * 1000;
        this.lastActivity = Date.now();
        this.init();
    }
    
    init() {
        // Track user activity
        document.addEventListener('mousemove', this.updateActivity.bind(this));
        document.addEventListener('keypress', this.updateActivity.bind(this));
        document.addEventListener('click', this.updateActivity.bind(this));
        
        // Check session periodically
        setInterval(this.checkSession.bind(this), 60000); // Every minute
    }
    
    updateActivity() {
        this.lastActivity = Date.now();
        localStorage.setItem('last_activity', this.lastActivity);
    }
    
    checkSession() {
        const now = Date.now();
        const idleTime = now - this.lastActivity;
        
        if (idleTime > this.sessionTimeout) {
            this.logoutDueToInactivity();
        }
        
        // Refresh session token every 15 minutes
        if (idleTime < 900000) {
            this.refreshSession();
        }
    }
    
    logoutDueToInactivity() {
        console.log('Session expired due to inactivity');
        API.logout();
        window.location.href = '/?session=expired';
    }
    
    refreshSession() {
        // Refresh session token
        localStorage.setItem('session_refreshed', Date.now());
    }
    
    isValidSession() {
        const userData = localStorage.getItem('user_data');
        const sessionTime = localStorage.getItem('last_activity');
        
        if (!userData || !sessionTime) return false;
        
        const idleTime = Date.now() - parseInt(sessionTime);
        return idleTime < this.sessionTimeout;
    }
}

// Initialize session manager when dashboard loads
let sessionManager = null;

// Export configuration (if using modules)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { CONFIG, API, Security, SessionManager };
}
