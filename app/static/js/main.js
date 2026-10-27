/**
 * NetGuard AI - Core UI & Network Formatting Utilities
 */

// Format raw bytes to human readable string (B, KB, MB, GB, TB)
function formatBytes(bytes, decimals = 2) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Format speeds in bits or bytes per second
function formatSpeed(bytesPerSec) {
    if (!bytesPerSec || bytesPerSec === 0) return '0 B/s';
    const mbps = (bytesPerSec * 8) / (1000 * 1000);
    if (mbps >= 1.0) {
        return mbps.toFixed(2) + ' Mbps';
    }
    const kbps = (bytesPerSec * 8) / 1000;
    if (kbps >= 1.0) {
        return kbps.toFixed(1) + ' Kbps';
    }
    return formatBytes(bytesPerSec) + '/s';
}

// Global Toast Notification Helper
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toastId = 'toast_' + Date.now();
    let bgBorder = 'border-info';
    let icon = 'bi-info-circle text-info';

    if (type === 'success') {
        bgBorder = 'border-success';
        icon = 'bi-check-circle-fill text-success';
    } else if (type === 'danger' || type === 'error') {
        bgBorder = 'border-danger';
        icon = 'bi-exclamation-triangle-fill text-danger';
    } else if (type === 'warning') {
        bgBorder = 'border-warning';
        icon = 'bi-exclamation-circle text-warning';
    }

    const toastHtml = `
        <div id="${toastId}" class="toast soc-toast align-items-center ${bgBorder} border mb-2" role="alert" aria-live="assertive" aria-atomic="true" data-bs-delay="4000">
            <div class="d-flex">
                <div class="toast-body d-flex align-items-center gap-2">
                    <i class="bi ${icon} fs-5"></i>
                    <div>${message}</div>
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        </div>
    `;

    container.insertAdjacentHTML('beforeend', toastHtml);
    const toastEl = document.getElementById(toastId);
    const bsToast = new bootstrap.Toast(toastEl);
    bsToast.show();

    toastEl.addEventListener('hidden.bs.toast', () => {
        toastEl.remove();
    });
}

// Generic API caller with error handling
async function apiCall(endpoint, method = 'GET', body = null) {
    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    };
    if (body && (method === 'POST' || method === 'PUT')) {
        options.body = JSON.stringify(body);
    }

    try {
        const response = await fetch(endpoint, options);
        if (response.status === 401) {
            window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname);
            return null;
        }
        const data = await response.json();
        return { ok: response.ok, status: response.status, data: data };
    } catch (err) {
        console.error('API Error (' + endpoint + '):', err);
        showToast('Network request failed: ' + err.message, 'danger');
        return { ok: false, error: err };
    }
}

// Mobile sidebar toggle handler
document.addEventListener('DOMContentLoaded', () => {
    const toggleBtn = document.getElementById('sidebarToggle');
    const sidebar = document.getElementById('sidebar-wrapper');
    if (toggleBtn && sidebar) {
        toggleBtn.addEventListener('click', () => {
            sidebar.classList.toggle('toggled');
        });
    }
});
