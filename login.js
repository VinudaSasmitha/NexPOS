const loginForm = document.getElementById('loginForm');
const loginBtn = document.getElementById('loginBtn');
const errorDiv = document.getElementById('errorMessage');

loginForm.addEventListener('submit', async function (e) {
    e.preventDefault();

    // Get values
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;

    // Reset UI
    hideError();
    setLoading(true);

    try {
        // Backend API call
        const response = await fetch('http://localhost:5000/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                Email: email,
                Password: password
            })
        });

        const data = await response.json();

        if (response.ok) {
            // ✅ SUCCESS: Save to Storage
            localStorage.setItem('pos_token', data.token);
            localStorage.setItem('pos_user', JSON.stringify(data.user));

            // ✅ REDIRECT: Based on Role

            if (data.user.role === 'Cashier') {
                window.location.href = 'bill.html';
            } else if (data.user.role === 'Admin' || data.user.role === 'Sales Manager' || data.user.role === 'Branch Manager') {
                window.location.href = 'dashboard.html';
            } else {
                // Default Dashboard
                window.location.href = 'dashboard.html';
            }
        } else {
            // ❌ FAILED: Show error from server
            showError(data.message || 'Invalid email or password.');
        }

    } catch (error) {
        console.error('Connection Error:', error);
        showError('Cannot connect to server. Check if Backend is running.');
    } finally {
        setLoading(false);
    }
});

function showError(message) {
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
}

function hideError() {
    errorDiv.style.display = 'none';
}

function setLoading(isLoading) {
    if (isLoading) {
        loginBtn.disabled = true;
        loginBtn.textContent = 'Signing in...';
    } else {
        loginBtn.disabled = false;
        loginBtn.textContent = 'Sign In';
    }
}

// Auto-Redirect if already logged in
window.onload = function () {
    const token = localStorage.getItem('pos_token');
    const userStr = localStorage.getItem('pos_user');

    if (token && userStr) {
        const user = JSON.parse(userStr);
        if (user.role === 'Cashier') {
            window.location.href = 'bill.html';
        } else {
            window.location.href = 'dashboard.html';
        }
    }
};
