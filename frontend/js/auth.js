// Enhanced authentication JavaScript with CSRF protection
document.addEventListener('DOMContentLoaded', function() {
    initializeCSRFProtection();
    
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const resetForm = document.getElementById('resetForm');
    
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
        addPasswordStrengthIndicator(loginForm);
    }
    
    if (signupForm) {
        signupForm.addEventListener('submit', handleSignup);
        addPasswordStrengthIndicator(signupForm);
        addRealTimeValidation(signupForm);
    }
    
    if (resetForm) {
        resetForm.addEventListener('submit', handleResetPassword);
    }
});

// CSRF Token management
function initializeCSRFProtection() {
    // Get CSRF token from meta tag
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
    if (csrfToken) {
        // Set default headers for all fetch requests
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            const [resource, config = {}] = args;
            config.headers = {
                ...config.headers,
                'X-CSRF-TOKEN': csrfToken
            };
            return originalFetch(resource, config);
        };
    }
}

function addPasswordStrengthIndicator(form) {
    const passwordInput = form.querySelector('input[type="password"]');
    if (!passwordInput) return;

    const strengthMeter = document.createElement('div');
    strengthMeter.className = 'password-strength';
    strengthMeter.innerHTML = `
        <div class="strength-bar"></div>
        <div class="strength-text"></div>
    `;
    passwordInput.parentNode.appendChild(strengthMeter);

    passwordInput.addEventListener('input', function() {
        const strength = calculatePasswordStrength(this.value);
        updateStrengthMeter(strengthMeter, strength);
    });
}

function calculatePasswordStrength(password) {
    let score = 0;
    if (!password) return { score: 0, text: 'Very Weak', color: '#ef4444' };

    // Length check
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;

    // Character variety
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;

    const levels = [
        { score: 0, text: 'Very Weak', color: '#ef4444' },
        { score: 2, text: 'Weak', color: '#f59e0b' },
        { score: 3, text: 'Fair', color: '#eab308' },
        { score: 4, text: 'Good', color: '#84cc16' },
        { score: 5, text: 'Strong', color: '#22c55e' },
        { score: 6, text: 'Very Strong', color: '#16a34a' }
    ];

    return levels.find(level => score <= level.score) || levels[levels.length - 1];
}

function updateStrengthMeter(meter, strength) {
    const bar = meter.querySelector('.strength-bar');
    const text = meter.querySelector('.strength-text');
    
    bar.style.width = `${(strength.score / 6) * 100}%`;
    bar.style.backgroundColor = strength.color;
    text.textContent = strength.text;
    text.style.color = strength.color;
}

function addRealTimeValidation(form) {
    const inputs = form.querySelectorAll('input[required]');
    inputs.forEach(input => {
        input.addEventListener('blur', function() {
            validateField(this);
        });
    });
}

function validateField(field) {
    const value = field.value.trim();
    let isValid = true;
    let message = '';

    switch (field.type) {
        case 'email':
            isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
            message = isValid ? '' : 'Please enter a valid email address';
            break;
        case 'tel':
            isValid = /^\+?[\d\s\-\(\)]{10,}$/.test(value);
            message = isValid ? '' : 'Please enter a valid phone number';
            break;
        case 'text':
            if (field.name === 'username') {
                isValid = value.length >= 3 && value.length <= 80;
                message = isValid ? '' : 'Username must be 3-80 characters';
            }
            break;
    }

    updateFieldValidationUI(field, isValid, message);
    return isValid;
}

function updateFieldValidationUI(field, isValid, message) {
    field.style.borderColor = isValid ? '#22c55e' : '#ef4444';
    
    let feedback = field.parentNode.querySelector('.validation-feedback');
    if (!feedback) {
        feedback = document.createElement('div');
        feedback.className = 'validation-feedback';
        field.parentNode.appendChild(feedback);
    }
    
    feedback.textContent = message;
    feedback.style.color = '#ef4444';
    feedback.style.fontSize = '0.875rem';
    feedback.style.marginTop = '0.25rem';
}

async function handleLogin(e) {
    e.preventDefault();
    
    if (!validateForm(e.target)) return;
    
    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Signing in...';
    
    try {
        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);
        
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        
        if (response.ok) {
            window.location.href = await getRedirectUrl();
        } else {
            const error = await response.json();
            showAlert(error.message || 'Login failed', 'error');
        }
    } catch (error) {
        showAlert('Network error. Please try again.', 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Login';
    }
}

async function handleSignup(e) {
    e.preventDefault();
    
    if (!validateForm(e.target)) return;
    
    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Creating Account...';
    
    try {
        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);
        
        const response = await fetch('/auth/signup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        
        if (response.ok) {
            showAlert('Account created successfully! Redirecting to login...', 'success');
            setTimeout(() => {
                window.location.href = '/auth/login';
            }, 2000);
        } else {
            const error = await response.json();
            showAlert(error.message || 'Signup failed', 'error');
        }
    } catch (error) {
        showAlert('Network error. Please try again.', 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Sign Up';
    }
}

function validateForm(form) {
    let isValid = true;
    const inputs = form.querySelectorAll('input[required]');
    
    inputs.forEach(input => {
        if (!validateField(input)) {
            isValid = false;
        }
    });
    
    return isValid;
}

async function getRedirectUrl() {
    try {
        const response = await fetch('/api/user/role');
        const data = await response.json();
        
        switch (data.role) {
            case 'admin': return '/admin/dashboard';
            case 'doctor': return '/doctor/dashboard';
            default: return '/patient/dashboard';
        }
    } catch {
        return '/dashboard';
    }
}

// Enhanced alert system
function showAlert(message, type) {
    // Remove existing alerts
    const existingAlerts = document.querySelectorAll('.custom-alert');
    existingAlerts.forEach(alert => alert.remove());
    
    const alertDiv = document.createElement('div');
    alertDiv.className = `custom-alert alert-${type}`;
    alertDiv.innerHTML = `
        <span>${message}</span>
        <button onclick="this.parentElement.remove()">&times;</button>
    `;
    
    alertDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        border-radius: 0.5rem;
        color: white;
        font-weight: 500;
        z-index: 10000;
        background: ${type === 'success' ? '#10b981' : '#ef4444'};
        display: flex;
        align-items: center;
        gap: 1rem;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
    `;
    
    alertDiv.querySelector('button').style.cssText = `
        background: none;
        border: none;
        color: white;
        font-size: 1.5rem;
        cursor: pointer;
        padding: 0;
        width: 24px;
        height: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
    `;
    
    document.body.appendChild(alertDiv);
    
    setTimeout(() => {
        if (alertDiv.parentElement) {
            alertDiv.remove();
        }
    }, 5000);
}