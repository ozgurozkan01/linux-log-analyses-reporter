document.addEventListener('DOMContentLoaded', function () {

    // --- DASHBOARD BAŞLANGIÇ AYARLARI ---
    const data = window.DashboardData || {};
    const volumeLabels = data.volumeLabels || [];
    const volumeData = data.volumeData || [];
    const heatmapData = data.heatmapData || [];
    const firewallStats = data.firewallStats || { allow: 0, deny: 0 };

    // Diff Modal'ını burda tanımlıyoruz (Sayfa yüklendiğinde hazır olsun)
    const diffModalEl = document.getElementById('diffModal');
    if (diffModalEl) {
        window.diffModalObj = new bootstrap.Modal(diffModalEl);
    }

    // --- TEMA AYARLARI (DARK/LIGHT) ---
    const html = document.documentElement;
    if (!localStorage.getItem('theme')) {
        localStorage.setItem('theme', 'dark');
        html.setAttribute('data-bs-theme', 'dark');
    } else {
        html.setAttribute('data-bs-theme', localStorage.getItem('theme'));
    }

    const toggleBtn = document.getElementById('darkModeToggle');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            const isDark = html.getAttribute('data-bs-theme') === 'dark';
            const newTheme = isDark ? 'light' : 'dark';
            html.setAttribute('data-bs-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        });
    }

    function getChartColors() {
        return {
            text: '#888ea8',
            grid: '#1b213b',
            bar: '#4f46e5'
        };
    }

    // --- HEATMAP OLUŞTURMA ---
    const heatmapEl = document.getElementById('eventHeatmap');
    if (heatmapEl && heatmapData.length > 0) {
        const maxVal = Math.max(...heatmapData) || 1;
        heatmapData.forEach((count, i) => {
            const cell = document.createElement('div');
            cell.classList.add('heatmap-cell');
            let intensity = 0;
            if (count > 0) intensity = Math.ceil((count / maxVal) * 5);

            cell.classList.add(`hm-${intensity}`);
            cell.title = `${String(i).padStart(2, '0')}:00 - ${count} logs`;
            heatmapEl.appendChild(cell);
        });
    }

    // --- VOLUME CHART (BAR) ---
    const ctxVol = document.getElementById('volumeChart');
    if (ctxVol) {
        new Chart(ctxVol.getContext('2d'), {
            type: 'bar',
            data: {
                labels: volumeLabels,
                datasets: [{
                    label: 'Logs',
                    data: volumeData,
                    backgroundColor: '#4f46e5',
                    borderRadius: 2,
                    hoverBackgroundColor: '#00d4ff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: getChartColors().text, font: { size: 10, family: 'monospace' } }
                    },
                    y: {
                        grid: { display: true, color: getChartColors().grid },
                        ticks: { color: getChartColors().text, font: { size: 10, family: 'monospace' } },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    // --- FIREWALL CHART (DOUGHNUT) ---
    const ctxFire = document.getElementById('firewallChart');
    if (ctxFire) {
        new Chart(ctxFire.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Allow', 'Deny'],
                datasets: [{
                    data: [firewallStats.allow, firewallStats.deny],
                    backgroundColor: ['#00ff88', '#ef4444'],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '75%',
                plugins: { legend: { display: false } }
            }
        });
    }

    // --- CANLI VERİ AKIŞI (LIVE STATS) ---
    setInterval(function () {
        fetch('/api/live-stats')
            .then(r => r.json())
            .then(data => {
                if (document.getElementById('live-uptime')) document.getElementById('live-uptime').innerText = data.uptime;
                if (document.getElementById('live-cpu-text')) document.getElementById('live-cpu-text').innerText = '%' + data.cpu;
                if (document.getElementById('live-ram-text')) document.getElementById('live-ram-text').innerText = '%' + data.ram;

                const tableBody = document.getElementById('live-process-list');
                if (tableBody && data.processes) {
                    let htmlContent = '';

                    for (let i = 0; i < 8; i++) {
                        if (i < data.processes.length) {
                            const proc = data.processes[i];

                            let userClass = 'proc-user';
                            if (proc.username === 'root') userClass = 'proc-root';
                            else if (['system', 'network'].includes(proc.username)) userClass = 'proc-sys';

                            let barColor = '#22c55e';
                            let riskBadge = 'SAFE';
                            let badgeBg = 'rgba(34, 197, 94, 0.1)';
                            let badgeText = '#22c55e';

                            if (proc.cpu_percent > 80) {
                                barColor = '#ef4444';
                                riskBadge = 'CRIT';
                                badgeBg = 'rgba(239, 68, 68, 0.2)';
                                badgeText = '#ef4444';
                            } else if (proc.cpu_percent > 40) {
                                barColor = '#facc15';
                                riskBadge = 'WARN';
                                badgeBg = 'rgba(250, 204, 21, 0.1)';
                                badgeText = '#facc15';
                            }

                            htmlContent += `
                                <div class="process-row">
                                    <div class="d-flex align-items-center" style="width: 40%;">
                                        <i class="fas fa-cog me-2 ${userClass}" style="font-size: 0.7rem;"></i>
                                        <div>
                                            <div class="fw-bold text-white text-truncate" style="font-size: 0.75rem; max-width: 80px;">${proc.name}</div>
                                            <div class="font-monospace text-muted" style="font-size: 0.6rem;">${proc.pid}</div>
                                        </div>
                                    </div>
                                    <div class="text-muted small text-truncate" style="width: 20%; font-size: 0.7rem;">${proc.username}</div>
                                    <div style="width: 35%;">
                                        <div class="d-flex justify-content-between align-items-center mb-1">
                                            <span class="fw-bold" style="color: ${barColor}; font-size: 0.7rem;">${proc.cpu_percent}%</span>
                                            <span style="background: ${badgeBg}; color: ${badgeText}; padding: 1px 4px; border-radius: 4px; font-size: 0.55rem; font-weight: bold;">${riskBadge}</span>
                                        </div>
                                        <div class="cpu-track">
                                            <div class="cpu-fill" style="width: ${proc.cpu_percent}%; background-color: ${barColor};"></div>
                                        </div>
                                    </div>
                                </div>`;
                        } else {
                            htmlContent += `
                                <div class="process-row" style="opacity: 0.3;">
                                    <span class="text-muted small">-</span>
                                </div>`;
                        }
                    }
                    tableBody.innerHTML = htmlContent;
                }
            })
            .catch(e => console.log('Live stats error:', e));
    }, 1000);
});

function resolveAlert(alertId) {
    if (!confirm("Are you sure you want to resolve this anomaly? This will reduce the threat level.")) {
        return;
    }

    fetch(`/api/resolve_alert/${alertId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(response => {
            if (response.ok) {
                const card = document.getElementById(`alert-card-${alertId}`);
                if (card) {
                    card.style.transition = "all 0.5s ease";
                    card.style.opacity = "0";
                    card.style.transform = "translateX(20px)";
                    setTimeout(() => card.remove(), 500);
                }

                updateAnomalyBadgeCount();
            } else {
                alert("Error resolving alert. Please check server logs.");
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
}

function formatDetails(rawText) {
    // Gelen veriyi kontrol et, boşsa işlem yapma
    if (!rawText) return "No details available.";

    const lines = rawText.split('\n').filter(line => line.trim() !== '');
    
    let data = {
        eventType: 'UNKNOWN',
        origPath: '',
        newPath: '',
        inode: '',
        uid: '',
        gid: '',
        oldPerms: '',
        newPerms: '',
        oldHash: '',
        newHash: '',
        analysis: ''
    };

    lines.forEach(line => {
        // İki noktaya göre böl ama sadece ilkini dikkate al (Hash içinde : olabilir)
        const firstColonIndex = line.indexOf(':');
        if (firstColonIndex === -1) return;

        const key = line.substring(0, firstColonIndex).trim().toUpperCase(); // Key'i büyük harfe çevirip karşılaştıracağız
        const val = line.substring(firstColonIndex + 1).trim();

        if (key.includes('EVENT TYPE')) data.eventType = val;
        else if (key.includes('ORIGINAL PATH')) data.origPath = val;
        else if (key.includes('NEW PATH')) data.newPath = val;
        else if (key.includes('INODE')) data.inode = val;
        else if (key === 'UID') data.uid = val;
        else if (key === 'GID') data.gid = val;
        else if (key.includes('OLD PERMISSIONS')) data.oldPerms = val;
        else if (key.includes('NEW PERMISSIONS')) data.newPerms = val;
        else if (key.includes('OLD HASH')) data.oldHash = val;
        else if (key.includes('NEW HASH')) data.newHash = val;
        else if (key.includes('ANALYSIS')) data.analysis = val;
    });

    // Permission değişimi var mı?
    const isPermChanged = (data.oldPerms && data.newPerms && data.oldPerms !== data.newPerms);

    // --- HTML ŞABLONU ---
    return `
        <div class="detail-box">
            <!-- 1. Üst Başlık -->
            <div class="info-row">
                <div class="info-card">
                    <span class="info-label">Event Context</span>
                    <span class="event-badge">${data.eventType}</span>
                </div>
                <div class="info-card">
                    <span class="info-label">File Metadata</span>
                    <div class="d-flex gap-3 text-white small font-monospace">
                        <div><span class="text-muted">UID:</span> ${data.uid || 'N/A'}</div>
                        <div><span class="text-muted">GID:</span> ${data.gid || 'N/A'}</div>
                        <div><span class="text-muted">INODE:</span> ${data.inode || 'N/A'}</div>
                    </div>
                </div>
            </div>

            <!-- 2. Permissions -->
            ${(data.oldPerms || data.newPerms) ? `
            <div class="info-row">
                <div class="info-card ${isPermChanged ? 'border-danger' : ''}">
                    <span class="info-label">Permissions Check</span>
                    <div class="d-flex align-items-center justify-content-between">
                        ${data.oldPerms ? `<span class="badge bg-secondary font-monospace">${data.oldPerms}</span>` : '<span>-</span>'}
                        <i class="fas fa-arrow-right text-muted mx-2" style="font-size: 0.8rem;"></i>
                        ${data.newPerms ? `<span class="badge ${isPermChanged ? 'bg-danger' : 'bg-success'} font-monospace">${data.newPerms}</span>` : '<span>-</span>'}
                    </div>
                </div>
            </div>` : ''}

            <!-- 3. HASH KONTROLÜ (Hash kutularını oluşturur) -->
            ${(data.oldHash || data.newHash) ? `
            <div class="path-comparison mt-2">
                <div class="info-label mb-2"><i class="fas fa-fingerprint me-1"></i> Content Integrity (SHA256)</div>
                
                ${data.oldHash ? `
                <div class="hash-block mb-2">
                    <small class="text-danger d-block mb-1">Previous Hash</small>
                    <div class="hash-value">${data.oldHash}</div>
                </div>` : ''}

                ${data.newHash ? `
                <div class="hash-block">
                    <small class="text-success d-block mb-1">Current Hash</small>
                    <div class="hash-value">${data.newHash}</div>
                </div>` : ''}
            </div>` : ''}

            <!-- 4. Dosya Yolu -->
            ${(data.origPath || data.newPath) ? `
            <div class="path-comparison mt-2">
                <div class="info-label mb-2">File Path Operations</div>
                ${data.origPath ? `<div class="path-text path-old mb-1">${data.origPath}</div>` : ''}
                ${(data.origPath && data.newPath) ? `<div class="text-center my-1"><i class="fas fa-arrow-down text-muted"></i></div>` : ''}
                ${data.newPath ? `<div class="path-text path-new">${data.newPath}</div>` : ''}
            </div>` : ''}

            <!-- 5. Analiz -->
            ${data.analysis ? `
            <div class="analysis-box mt-3">
                <i class="fas fa-search me-2 mt-1"></i>
                <div>
                    <strong style="display:block; margin-bottom:2px;">Detection Analysis</strong>
                    ${data.analysis}
                </div>
            </div>` : ''}
        </div>
    `;
}

function openDetailModal(alertId) {
    const rawDetails = document.getElementById(`raw-details-${alertId}`).innerText;
    const contentDiv = document.getElementById('diffContent');

    contentDiv.innerHTML = formatDetails(rawDetails);

    var myModal = new bootstrap.Modal(document.getElementById('diffModal'));
    myModal.show();
}

function updateAnomalyBadgeCount() {
    const badge = document.querySelector('.card-header .badge');
    if (badge) {
        let text = badge.innerText;
        let currentCount = parseInt(text.match(/\d+/)[0]);
        if (currentCount > 0) {
            currentCount--;
            badge.innerText = `${currentCount} ANOMALIES`;

            if (currentCount === 0) {
                setTimeout(() => location.reload(), 600);
            }
        }
    }
}

function escapeHtml(text) {
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}