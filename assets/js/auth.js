/**
 * Authentication Module
 * Handles login, signup, and session management
 */

class AuthManager {
    constructor() {
        this.currentForm = 'login';
        this.initializeEventListeners();
        this.checkAutoLogin();
    }
    
    initializeEventListeners() {
        // Form switching
        $('#switchToSignup').on('click', (e) => {
            e.preventDefault();
            this.switchForm('signup');
        });
        
        $('#switchToLogin').on('click', (e) => {
            e.preventDefault();
            this.switchForm('login');
        });
        
        $('#backToLogin').on('click', (e) => {
            e.preventDefault();
            this.switchForm('login');
        });
        
        $('a[href="#forgot-password"]').on('click', (e) => {
            e.preventDefault();
            this.switchForm('forgot');
        });
        
        // Form submissions
        $('#loginFormElement').on('submit', (e) => this.handleLogin(e));
        $('#signupFormElement').on('submit', (e) => this.handleSignup(e));
        $('#forgotFormElement').on('submit', (e) => this.handleForgotPassword(e));
        
        // Password visibility toggle
        $('#togglePassword').on('click', () => this.togglePassword('password'));
        $('#toggleSignupPassword').on('click', () => this.togglePassword('signupPassword'));
        
        // Password strength indicator
        $('#signupPassword').on('input', () => this.updatePasswordStrength());
    }
    
    switchForm(formName) {
        $('.form-container').removeClass('active');
        $(`#${formName}Form`).addClass('active');
        this.clearAlerts();
        this.currentForm = formName;
        
        // Update URL hash
        window.location.hash = formName;
    }
    
    async handleLogin(e) {
        e.preventDefault();
        
        const email = $('#email').val().trim();
        const password = $('#password').val();
        const rememberMe = $('#rememberMe').is(':checked');
        
        // Validation
        if (!this.validateEmail(email)) {
            this.showAlert('login', 'Please enter a valid email address', 'error');
            return;
        }
        
        if (password.length < 8) {
            this.showAlert('login', 'Password must be at least 8 characters', 'error');
            return;
        }
        
        // Update button state
        $('#loginBtn').prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Signing in...');
        
        try {
            const response = await API.login(email, password);
            
            if (response.success) {
                // Store user data
                localStorage.setItem('user_data', JSON.stringify(response.user));
                localStorage.setItem('auth_token', response.token);
                localStorage.setItem('last_activity', Date.now());
                
                if (rememberMe) {
                    localStorage.setItem('remember_me', 'true');
                }
                
                // Show success message
                this.showAlert('login', 'Login successful! Redirecting...', 'success');
                
                // Redirect to dashboard
                setTimeout(() => {
                    window.location.href = 'dashboard.html';
                }, 1000);
            } else {
                this.showAlert('login', response.message || 'Invalid credentials', 'error');
                $('#loginBtn').prop('disabled', false).html('<span class="btn-text">Sign In</span><i class="fas fa-arrow-right"></i>');
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showAlert('login', 'Connection error. Please try again.', 'error');
            $('#loginBtn').prop('disabled', false).html('<span class="btn-text">Sign In</span><i class="fas fa-arrow-right"></i>');
        }
    }
    
    async handleSignup(e) {
        e.preventDefault();
        
        const username = $('#username').val().trim();
        const email = $('#signupEmail').val().trim();
        const password = $('#signupPassword').val();
        const confirmPassword = $('#confirmPassword').val();
        const agreeTerms = $('#agreeTerms').is(':checked');
        
        // Validation
        if (username.length < 3 || username.length > 20) {
            this.showAlert('signup', 'Username must be 3-20 characters', 'error');
            return;
        }
        
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            this.showAlert('signup', 'Username can only contain letters, numbers, and underscores', 'error');
            return;
        }
        
        if (!this.validateEmail(email)) {
            this.showAlert('signup', 'Please enter a valid email address', 'error');
            return;
        }
        
        if (password.length < 8) {
            this.showAlert('signup', 'Password must be at least 8 characters', 'error');
            return;
        }
        
        if (password !== confirmPassword) {
            this.showAlert('signup', 'Passwords do not match', 'error');
            return;
        }
        
        if (!agreeTerms) {
            this.showAlert('signup', 'You must agree to the Terms of Service', 'error');
            return;
        }
        
        // Update button state
        $('#signupBtn').prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Creating account...');
        
        try {
            const response = await API.signup({
                username,
                email,
                password,
                newsletter: $('#newsletter').is(':checked')
            });
            
            if (response.success) {
                this.showAlert('signup', 'Account created successfully! Redirecting to login...', 'success');
                
                // Clear form
                $('#signupFormElement')[0].reset();
                
                // Switch to login form after delay
                setTimeout(() => {
                    this.switchForm('login');
                    $('#email').val(email);
                }, 2000);
            } else {
                this.showAlert('signup', response.message || 'Registration failed', 'error');
            }
        } catch (error) {
            console.error('Signup error:', error);
            this.showAlert('signup', 'Connection error. Please try again.', 'error');
        } finally {
            $('#signupBtn').prop('disabled', false).html('<span class="btn-text">Create Account</span><i class="fas fa-check"></i>');
        }
    }
    
    async handleForgotPassword(e) {
        e.preventDefault();
        
        const email = $('#resetEmail').val().trim();
        
        if (!this.validateEmail(email)) {
            this.showAlert('forgot', 'Please enter a valid email address', 'error');
            return;
        }
        
        $('#resetBtn').prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Sending...');
        
        try {
            // Simulate API call
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            this.showAlert('forgot', 'If an account exists with this email, you will receive reset instructions.', 'success');
            $('#resetEmail').val('');
            
            setTimeout(() => {
                this.switchForm('login');
            }, 3000);
        } catch (error) {
            this.showAlert('forgot', 'Error sending reset email', 'error');
        } finally {
            $('#resetBtn').prop('disabled', false).html('<span class="btn-text">Send Reset Link</span><i class="fas fa-paper-plane"></i>');
        }
    }
    
    validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    }
    
    togglePassword(inputId) {
        const input = $(`#${inputId}`);
        const button = $(`#toggle${inputId.charAt(0).toUpperCase() + inputId.slice(1)}`);
        const icon = button.find('i');
        
        if (input.attr('type') === 'password') {
            input.attr('type', 'text');
            icon.removeClass('fa-eye').addClass('fa-eye-slash');
        } else {
            input.attr('type', 'password');
            icon.removeClass('fa-eye-slash').addClass('fa-eye');
        }
    }
    
    updatePasswordStrength() {
        const password = $('#signupPassword').val();
        const strengthBar = $('#passwordStrength');
        const strengthText = $('#strengthText');
        
        let strength = 0;
        let text = 'Very Weak';
        let color = '#ef4444';
        
        if (password.length >= 8) strength += 25;
        if (/[A-Z]/.test(password)) strength += 25;
        if (/[0-9]/.test(password)) strength += 25;
        if (/[^A-Za-z0-9]/.test(password)) strength += 25;
        
        if (strength >= 75) {
            text = 'Strong';
            color = '#10b981';
        } else if (strength >= 50) {
            text = 'Good';
            color = '#f59e0b';
        } else if (strength >= 25) {
            text = 'Weak';
            color = '#f59e0b';
        }
        
        strengthBar.css({
            width: strength + '%',
            backgroundColor: color
        });
        
        strengthText.text(text).css('color', color);
    }
    
    showAlert(form, message, type) {
        const alertBox = $(`#${form}Alert`);
        const icon = type === 'success' ? 'fa-check-circle' : 
                    type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle';
        
        alertBox.html(`
            <i class="fas ${icon}"></i>
            <span>${message}</span>
        `).removeClass('alert-success alert-error alert-info')
          .addClass(`alert-${type}`)
          .slideDown();
        
        if (type !== 'error') {
            setTimeout(() => {
                alertBox.slideUp();
            }, 5000);
        }
    }
    
    clearAlerts() {
        $('.alert-box').hide().removeClass('alert-success alert-error alert-info');
    }
    
    checkAutoLogin() {
        const rememberMe = localStorage.getItem('remember_me') === 'true';
        const userData = localStorage.getItem('user_data');
        
        if (rememberMe && userData) {
            try {
                const user = JSON.parse(userData);
                if (user && user.email) {
                    $('#email').val(user.email);
                    $('#rememberMe').prop('checked', true);
                }
            } catch (e) {
                console.error('Error parsing user data:', e);
            }
        }
        
        // Check URL hash for form
        const hash = window.location.hash.substring(1);
        if (['login', 'signup', 'forgot'].includes(hash)) {
            this.switchForm(hash);
        }
    }
}

// Initialize when DOM is ready
$(document).ready(() => {
    window.authManager = new AuthManager();
    
    // Handle browser back/forward
    $(window).on('hashchange', () => {
        const hash = window.location.hash.substring(1);
        if (['login', 'signup', 'forgot'].includes(hash)) {
            authManager.switchForm(hash);
        }
    });
});
