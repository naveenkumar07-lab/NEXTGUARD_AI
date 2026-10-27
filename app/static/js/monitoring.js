/**
 * NetGuard AI - Network Interface Monitoring & Packet Capture Controls
 */

document.addEventListener('DOMContentLoaded', () => {
    setupMonitoringControls();
    setupPacketCaptureControls();
    startMonitorPagePolling();
});

function setupMonitoringControls() {
    const btnStart = document.getElementById('btnStartReal');
    const btnStartDemo = document.getElementById('btnStartDemo');
    const btnStop = document.getElementById('btnStopMonitor');
    const ifaceSelect = document.getElementById('interfaceSelect');
    const intervalInput = document.getElementById('monitorInterval');

    if (btnStart) {
        btnStart.addEventListener('click', async () => {
            const iface = ifaceSelect ? ifaceSelect.value : null;
            const interval = intervalInput ? intervalInput.value : 2.0;
            const res = await apiCall('/api/monitoring/start', 'POST', {
                interface: iface,
                is_demo: false,
                interval: interval
            });
            if (res && res.ok) {
                showToast(res.data.message, 'success');
                setTimeout(() => location.reload(), 1000);
            } else {
                showToast(res ? res.data.message : 'Error starting real monitoring', 'danger');
            }
        });
    }

    if (btnStartDemo) {
        btnStartDemo.addEventListener('click', async () => {
            const interval = intervalInput ? intervalInput.value : 2.0;
            const res = await apiCall('/api/monitoring/start', 'POST', {
                is_demo: true,
                interval: interval
            });
            if (res && res.ok) {
                showToast(res.data.message, 'success');
                setTimeout(() => location.reload(), 1000);
            } else {
                showToast(res ? res.data.message : 'Error starting demo monitoring', 'danger');
            }
        });
    }

    if (btnStop) {
        btnStop.addEventListener('click', async () => {
            const res = await apiCall('/api/monitoring/stop', 'POST');
            if (res && res.ok) {
                showToast('Monitoring stopped successfully', 'info');
                setTimeout(() => location.reload(), 1000);
            } else {
                showToast(res ? res.data.message : 'Error stopping monitoring', 'warning');
            }
        });
    }
}

function setupPacketCaptureControls() {
    const btnStartCapture = document.getElementById('btnStartCapture');
    const btnStopCapture = document.getElementById('btnStopCapture');
    const captureIface = document.getElementById('captureInterfaceSelect');

    if (btnStartCapture) {
        btnStartCapture.addEventListener('click', async () => {
            const iface = captureIface ? captureIface.value : null;
            const res = await apiCall('/api/packet-capture/start', 'POST', { interface: iface });
            if (res && res.ok) {
                showToast(res.data.message, 'success');
                setTimeout(() => location.reload(), 1000);
            } else {
                showToast(res ? (res.data.message || res.data.error) : 'Failed to start packet capture', 'warning');
            }
        });
    }

    if (btnStopCapture) {
        btnStopCapture.addEventListener('click', async () => {
            const res = await apiCall('/api/packet-capture/stop', 'POST');
            if (res && res.ok) {
                showToast('Packet capture stopped', 'info');
                setTimeout(() => location.reload(), 1000);
            } else {
                showToast(res ? res.data.message : 'Failed to stop packet capture', 'warning');
            }
        });
    }
}

function startMonitorPagePolling() {
    setInterval(async () => {
        const res = await apiCall('/api/metrics/current');
        if (res && res.ok && res.data) {
            const d = res.data;
            const downBps = document.getElementById('liveDownBps');
            if (downBps) downBps.textContent = (d.download_speed_mbps || 0).toFixed(2) + ' Mbps';

            const upBps = document.getElementById('liveUpBps');
            if (upBps) upBps.textContent = (d.upload_speed_mbps || 0).toFixed(2) + ' Mbps';

            const pps = document.getElementById('livePps');
            if (pps) pps.textContent = Math.round(d.packet_rate_pps || 0).toLocaleString() + ' pps';

            const bytesRecv = document.getElementById('liveBytesRecv');
            if (bytesRecv) bytesRecv.textContent = formatBytes(d.bytes_recv || 0);

            const bytesSent = document.getElementById('liveBytesSent');
            if (bytesSent) bytesSent.textContent = formatBytes(d.bytes_sent || 0);
        }
    }, 2000);
}
