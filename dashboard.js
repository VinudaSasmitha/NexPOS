// Check Auth
window.onload = function () {
    const token = localStorage.getItem('pos_token');
    const userStr = localStorage.getItem('pos_user');

    if (!token || !userStr) {
        window.location.href = 'login.html';
        return;
    }

    const user = JSON.parse(userStr);
    document.getElementById('navUserName').textContent = user.Name;
    document.getElementById('navUserRole').textContent = user.role;

    // Show Admin Menu if role is Admin
    if (user.role === 'Admin' || user.role === 'Branch Manager') {
        document.getElementById('adminMenu').classList.remove('hidden');
    }

    fetchStats();
};

async function fetchStats() {
    const token = localStorage.getItem('pos_token');
    try {
        const response = await fetch('http://localhost:5000/api/dashboard/lowstock', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        document.getElementById('lowStockCount').textContent = data.length;
    } catch (err) { console.log(err); }
}

function logout() {
    localStorage.clear();
    window.location.href = 'login.html';
}
