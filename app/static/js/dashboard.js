/**
 * NetGuard AI - Live Dashboard Charts & Telemetry Polling
 */

let bandwidthChart = null;
let protocolChart = null;
let pollingInterval = null;
const MAX_CHART_POINTS = 30;

document.addEventListener('DOMContentLoaded', async () => {
    initCharts();
    await loadInitialHistory();
    startPolling();
    setupControls();
});

function initCharts() {
    // 1. Bandwidth Line Chart
    const bwCtx = document.getElementById('bandwidthChart');
    if (bwCtx) {
        bandwidthChart = new Chart(bwCtx.getContext('2d'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Download (Mbps)',
                        borderColor: '#00d2ff',
                        backgroundColor: 'rgba(0, 210, 255, 0.1)',
                        borderWidth: 2,
                        tension: 0.35,
                        fill: true,
                        data: [],
                        pointRadius: 1,
                        pointHoverRadius: 5
                    },
                    {
                        label: 'Upload (Mbps)',
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.08)',
                        borderWidth: 2,
                        tension: 0.35,
                        fill: true,
                        data: [],
                        pointRadius: 1,
                        pointHoverRadius: 5
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 400 },
                plugins: {
                    legend: {
                        labels: { color: '#94a3b8', font: { family: 'Plus Jakarta Sans', size: 12 } }
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        backgroundColor: '#0d1527',
                        titleColor: '#ffffff',
                        bodyColor: '#cbd5e1',
                        borderColor: 'rgba(0, 210, 255, 0.3)',
                        borderWidth: 1
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 }, maxTicksLimit: 8 }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    // 2. Protocol Distribution Doughnut Chart
    const protoCtx = document.getElementById('protocolChart');
    if (protoCtx) {
        protocolChart = new Chart(protoCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTPS', 'Other'],
                datasets: [{
                    data: [50, 20, 5, 10, 12, 3],
                    backgroundColor: [
                        '#00d2ff',
                        '#3b82f6',
                        '#f59e0b',
                        '#10b981',
                        '#8b5cf6',
                        '#64748b'
                    ],
                    borderWidth: 1,
                    borderColor: '#111c35'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', font: { family: 'Plus Jakarta Sans', size: 11 }, padding: 12 }
                    }
                },
                cutout: '68%'
            }
        });
    }
}

async function loadInitialHistory() {
    const res = await apiCall('/api/metrics/history?limit=25');
    if (res && res.ok && res.data && res.data.metrics) {
        const metrics = res.data.metrics;
        metrics.forEach(m => {
            const timeLabel = m.timestamp ? new Date(m.timestamp).toLocaleTimeString() : '';
            if (bandwidthChart) {
                bandwidthChart.data.labels.push(timeLabel);
                bandwidthChart.data.datasets[0].data.push(m.download_speed_mbps);
                bandwidthChart.data.datasets[1].data.push(m.upload_speed_mbps);
            }
        });
        if (bandwidthChart) bandwidthChart.update('none');

        if (metrics.length > 0) {
            const latest = metrics[metrics.length - 1];
            updateDashboardKPIs(latest);
            if (latest.protocols) {
                updateProtocolChart(latest.protocols);
            }
        }
    }
}

function startPolling() {
    if (pollingInterval) clearInterval(pollingInterval);
    pollingInterval = setInterval(pollMetrics, 2000);
}

async function pollMetrics() {
    const res = await apiCall('/api/metrics/current');
    if (res && res.ok && res.data) {
        const d = res.data;
        updateDashboardKPIs(d);

        // Update Bandwidth Chart
        if (bandwidthChart) {
            const timeLabel = new Date().toLocaleTimeString();
            bandwidthChart.data.labels.push(timeLabel);
            bandwidthChart.data.datasets[0].data.push(d.download_speed_mbps || 0);
            bandwidthChart.data.datasets[1].data.push(d.upload_speed_mbps || 0);

            if (bandwidthChart.data.labels.length > MAX_CHART_POINTS) {
                bandwidthChart.data.labels.shift();
                bandwidthChart.data.datasets[0].data.shift();
                bandwidthChart.data.datasets[1].data.shift();
            }
            bandwidthChart.update('none');
        }

        // Update Protocols
        if (d.protocols && protocolChart) {
            updateProtocolChart(d.protocols);
        }
    }

    // Also update health & alert indicators
    const statusRes = await apiCall('/api/status');
    if (statusRes && statusRes.ok && statusRes.data) {
        const s = statusRes.data;
        const alertsBadge = document.getElementById('activeAlertsCount');
        if (alertsBadge) alertsBadge.textContent = s.active_alerts_count;

        const healthScoreEl = document.getElementById('networkHealthScore');
        if (healthScoreEl) healthScoreEl.textContent = s.health_score + '%';

        const anomaliesCountEl = document.getElementById('totalAnomaliesCount');
        if (anomaliesCountEl) anomaliesCountEl.textContent = s.total_anomalies_count;
    }
}

function updateDashboardKPIs(data) {
    const downEl = document.getElementById('statDownloadSpeed');
    if (downEl) downEl.textContent = (data.download_speed_mbps || 0).toFixed(2);

    const upEl = document.getElementById('statUploadSpeed');
    if (upEl) upEl.textContent = (data.upload_speed_mbps || 0).toFixed(2);

    const ppsEl = document.getElementById('statPacketRate');
    if (ppsEl) ppsEl.textContent = Math.round(data.packet_rate_pps || 0).toLocaleString();

    const totalRecvEl = document.getElementById('statTotalRecv');
    if (totalRecvEl) totalRecvEl.textContent = formatBytes(data.bytes_recv || 0);

    const totalSentEl = document.getElementById('statTotalSent');
    if (totalSentEl) totalSentEl.textContent = formatBytes(data.bytes_sent || 0);

    const ifaceBadge = document.getElementById('activeInterfaceName');
    if (ifaceBadge) ifaceBadge.textContent = data.interface_name || 'None';

    const simBadge = document.getElementById('dataSourceBadge');
    if (simBadge) {
        if (data.is_demo) {
            simBadge.className = 'badge badge-soc badge-demo-sim';
            simBadge.innerHTML = '<i class="bi bi-cpu"></i> SIMULATED DATA';
        } else {
            simBadge.className = 'badge badge-soc badge-live-pulse';
            simBadge.innerHTML = '<i class="bi bi-broadcast"></i> REAL INTERFACE';
        }
    }
}

function updateProtocolChart(protocols) {
    if (!protocolChart) return;
    const tcp = protocols.tcp || 0;
    const udp = protocols.udp || 0;
    const icmp = protocols.icmp || 0;
    const dns = protocols.dns || 0;
    const https = protocols.https || 0;
    const other = (protocols.http || 0) + (protocols.other || 0);

    protocolChart.data.datasets[0].data = [tcp, udp, icmp, dns, https, other];
    protocolChart.update('none');
}

function setupControls() {
    // Quick Demo Scenario Switcher
    const scenarioSelect = document.getElementById('quickScenarioSelect');
    if (scenarioSelect) {
        scenarioSelect.addEventListener('change', async (e) => {
            const scenario = e.target.value;
            const res = await apiCall('/api/demo/scenario', 'POST', { scenario: scenario });
            if (res && res.ok) {
                showToast(`Simulation scenario switched to ${scenario}`, 'success');
            } else {
                showToast('Failed to switch scenario', 'danger');
            }
        });
    }

    // Monitoring Toggle Buttons on Dashboard
    const btnStart = document.getElementById('btnStartMonitoring');
    if (btnStart) {
        btnStart.addEventListener('click', async () => {
            const res = await apiCall('/api/monitoring/start', 'POST', { is_demo: true });
            if (res && res.ok) {
                showToast(res.data.message, 'success');
                setTimeout(() => location.reload(), 800);
            } else {
                showToast(res.data.message || 'Error starting monitoring', 'warning');
            }
        });
    }

    const btnStop = document.getElementById('btnStopMonitoring');
    if (btnStop) {
        btnStop.addEventListener('click', async () => {
            const res = await apiCall('/api/monitoring/stop', 'POST');
            if (res && res.ok) {
                showToast('Monitoring stopped', 'info');
                setTimeout(() => location.reload(), 800);
            } else {
                showToast(res.data.message || 'Error stopping monitoring', 'warning');
            }
        });
    }
}
