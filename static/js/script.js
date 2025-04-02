document.addEventListener('DOMContentLoaded', function() {
    // Password visibility toggle for encryption
    const togglePasswordBtn = document.getElementById('toggle-password');
    if (togglePasswordBtn) {
        togglePasswordBtn.addEventListener('click', function() {
            const passwordInput = document.getElementById('password');
            const icon = this.querySelector('i');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                passwordInput.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });
    }
    
    // Password visibility toggle for decryption
    const toggleDecryptPasswordBtn = document.getElementById('toggle-decrypt-password');
    if (toggleDecryptPasswordBtn) {
        toggleDecryptPasswordBtn.addEventListener('click', function() {
            const passwordInput = document.getElementById('decrypt-password');
            const icon = this.querySelector('i');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                passwordInput.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });
    }
    
    // Encryption method change handler
    const encryptionMethodSelect = document.getElementById('encryption_method');
    const passwordGroup = document.getElementById('password-group');
    
    if (encryptionMethodSelect && passwordGroup) {
        encryptionMethodSelect.addEventListener('change', function() {
            if (this.value === 'rsa' || this.value === 'ecc') {
                passwordGroup.style.display = 'none';
            } else {
                passwordGroup.style.display = 'block';
            }
        });
    }
    
    // Decryption method change handler
    const decryptionMethodSelect = document.getElementById('decryption_method');
    const decryptPasswordGroup = document.getElementById('decrypt-password-group');
    const privateKeyGroup = document.getElementById('private-key-group');
    
    if (decryptionMethodSelect && decryptPasswordGroup && privateKeyGroup) {
        decryptionMethodSelect.addEventListener('change', function() {
            if (this.value === 'rsa' || this.value === 'ecc') {
                decryptPasswordGroup.style.display = 'none';
                privateKeyGroup.style.display = 'block';
            } else {
                decryptPasswordGroup.style.display = 'block';
                privateKeyGroup.style.display = 'none';
            }
        });
    }
    
    // Password strength meter
    const passwordInput = document.getElementById('password');
    const passwordStrength = document.getElementById('password-strength');
    
    if (passwordInput && passwordStrength) {
        passwordInput.addEventListener('input', function() {
            const password = this.value;
            let strength = 0;
            let message = '';
            
            if (password.length >= 12) {
                strength += 1;
            }
            
            if (password.match(/[a-z]/) && password.match(/[A-Z]/)) {
                strength += 1;
            }
            
            if (password.match(/[0-9]/)) {
                strength += 1;
            }
            
            if (password.match(/[^a-zA-Z0-9]/)) {
                strength += 1;
            }
            
            switch (strength) {
                case 0:
                    message = 'For symmetric encryption (AES, 3DES), use a strong password';
                    passwordStrength.className = 'text-muted';
                    break;
                case 1:
                    message = 'Very Weak: Use a stronger password';
                    passwordStrength.className = 'text-danger';
                    break;
                case 2:
                    message = 'Weak: Consider a stronger password';
                    passwordStrength.className = 'text-warning';
                    break;
                case 3:
                    message = 'Medium: Good password';
                    passwordStrength.className = 'text-info';
                    break;
                case 4:
                    message = 'Strong: Excellent password';
                    passwordStrength.className = 'text-success';
                    break;
            }
            
            passwordStrength.textContent = message;
        });
    }
    
    // Initialize clipboard.js
    if (typeof ClipboardJS !== 'undefined') {
        new ClipboardJS('.btn[data-clipboard-target]').on('success', function(e) {
            const originalText = e.trigger.innerHTML;
            e.trigger.innerHTML = '<i class="fas fa-check"></i> Copied!';
            
            setTimeout(function() {
                e.trigger.innerHTML = originalText;
            }, 2000);
            
            e.clearSelection();
        });
    }
    
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert:not(.alert-success)');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
});
