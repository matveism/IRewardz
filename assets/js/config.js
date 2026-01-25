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
        // Use the fixed API service
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
