document.addEventListener('DOMContentLoaded', function () {

    const data = window.DashboardData || {};
    const volumeLabels = data.volumeLabels || [];
    const volumeData = data.volumeData || [];
    const heatmapData = data.heatmapData || [];
    const firewallStats = data.firewallStats || { allow: 0, deny: 0 };

    const diffModalEl = document.getElementById('diffModal');
    if (diffModalEl) {
        window.diffModalObj = new bootstrap.Modal(diffModalEl);
    }

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

    setInterval(function () {
        fetch('/api/live-stats')
            .then(r => r.json())
            .then(data => {
                // Üst bilgi güncellemeleri
                if (document.getElementById('live-uptime')) document.getElementById('live-uptime').innerText = data.uptime;
                if (document.getElementById('live-cpu-text')) document.getElementById('live-cpu-text').innerText = '%' + data.cpu;
                if (document.getElementById('live-ram-text')) document.getElementById('live-ram-text').innerText = '%' + data.ram;

                const tableBody = document.getElementById('live-process-list');

                if (tableBody && data.processes) {
                    let htmlContent = '';

                    for (let i = 0; i < data.processes.length; i++) {
                        const proc = data.processes[i];

                        if (proc.cpu_percent <= 0.1 && proc.memory_percent <= 0.1) {
                            continue;
                        }

                        const isHeavy = (proc.cpu_percent > 25 || proc.memory_percent > 25);
                        const isRoot = (proc.username === 'root');
                        const isSystem = ['system', 'daemon', 'messagebus'].includes(proc.username);

                        const rowOpacity = (isHeavy || (!isRoot && !isSystem)) ? '1' : '0.4';
                        const rowBg = isHeavy
                            ? 'linear-gradient(90deg, rgba(255, 72, 0, 0.15) 0%, rgba(255, 72, 0, 0.0) 100%)'
                            : 'transparent';

                        const borderStyle = isHeavy
                            ? 'border-left: 3px solid #ff4800;'
                            : 'border-left: 3px solid transparent;';

                        const userIcon = isRoot ? 'fa-shield-alt' : 'fa-user';
                        const userColor = isRoot ? '#dc3545' : '#38bdf8';

                        let barColor = '#22c55e';
                        if (proc.cpu_percent > 50) barColor = '#ef4444';
                        else if (proc.cpu_percent > 20) barColor = '#facc15';

                        let displayName = proc.name;
                        let countBadgeHtml = '';

                        if (proc.name.includes('(') && proc.name.includes(')')) {
                            const parts = proc.name.split('(');
                            displayName = parts[0].trim();
                            const countVal = parts[1].replace(')', '').trim();

                            countBadgeHtml = `
                            <span class="badge bg-secondary bg-opacity-25 text-white border border-secondary border-opacity-25 rounded-pill me-2" 
                                  style="font-size: 0.55rem; padding: 2px 5px; color: white !important;">
                                ${countVal}
                            </span>`;
                        }

                        const ramVal = proc.memory_percent ? parseFloat(proc.memory_percent).toFixed(1) : '0.0';

                        htmlContent += `
                        <div class="process-item p-2 rounded d-flex align-items-center" 
                             title="PID: ${proc.pid}"
                             style="opacity: ${rowOpacity}; background: ${rowBg}; ${borderStyle} transition: all 0.3s ease; margin-bottom: 4px;">
                            
                            <div style="width: 45%; min-width: 0;">
                                <div class="d-flex align-items-center mb-1">
                                    <span class="fw-bold text-white text-truncate me-2" style="font-size: 0.8rem;">
                                        ${displayName}
                                    </span>
                                    ${countBadgeHtml}
                                    <span class="font-monospace small" style="font-size: 0.85rem; color: rgba(209, 205, 205, 0.4);">#${proc.pid}</span>
                                </div>
                            </div>

                            <div style="width: 20%;" class="d-flex justify-content-center align-items-center">
                                <div class="d-flex align-items-center gap-1"
                                    style="padding: 3px 6px; min-width: 50px; justify-content: center;">
                                    <i class="fas ${userIcon}" style="font-size: 0.55rem; color: ${userColor};"></i>
                                    <span style="font-size: 0.8rem; color: #94a3b8;">
                                        ${proc.username.substring(0, 5)}
                                    </span>
                                </div>
                            </div>

                            <div style="width: 35%;" class="d-flex justify-content-end align-items-center gap-2 pe-1">
                                <div class="text-end lh-1">
                                    <div class="font-monospace fw-bold" style="color: ${barColor}; font-size: 0.75rem;">${proc.cpu_percent}%</div>
                                </div>
                                <div style="width: 1px; height: 12px; background: rgba(255,255,255,0.1);"></div>
                                <div class="text-end lh-1">
                                    <div class="font-monospace fw-bold" style="color: #38bdf8; font-size: 0.75rem;">${ramVal}%</div>
                                </div>
                            </div>
                        </div>`;
                    }

                    if (htmlContent === '') {
                        htmlContent = '<div class="text-center p-4 text-muted small" style="opacity:0.5;">No active processes detected.</div>';
                    }

                    tableBody.innerHTML = htmlContent;
                }
            })
            .catch(e => console.log('Live stats error:', e));
    }, 2000);
});

let targetAlertId = null;
let resolveModalObj = null;

function resolveAlert(alertId) {
    targetAlertId = alertId;
    document.getElementById('resolveNote').value = '';
    document.getElementById('resolveAlertId').value = alertId;

    const modalEl = document.getElementById('resolveModal');
    if (modalEl) {
        resolveModalObj = new bootstrap.Modal(modalEl);
        resolveModalObj.show();
    }
}

function confirmResolution() {
    if (!targetAlertId) return;

    const note = document.getElementById('resolveNote').value;
    const finalNote = note.trim() === '' ? 'Hızlı kapatma (Not girilmedi)' : note;

    fetch(`/api/resolve_alert/${targetAlertId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: finalNote })
    })
        .then(response => {
            if (response.ok) {
                if (resolveModalObj) resolveModalObj.hide();

                const card = document.getElementById(`alert-card-${targetAlertId}`);
                if (card) {
                    card.style.transition = "all 0.5s ease";
                    card.style.transform = "translateX(50px)";
                    card.style.opacity = "0";
                }

                setTimeout(() => {
                    location.reload();
                }, 500);

            } else {
                alert("Hata oluştu. Lütfen tekrar deneyin.");
            }
        })
        .catch(err => {
            console.error(err);
            alert("Sunucuyla bağlantı kurulamadı.");
        });
}

document.addEventListener('DOMContentLoaded', function () {

    const html = document.documentElement;
    if (!localStorage.getItem('theme')) {
        localStorage.setItem('theme', 'dark');
        html.setAttribute('data-bs-theme', 'dark');
    } else {
        html.setAttribute('data-bs-theme', localStorage.getItem('theme'));
    }

    setInterval(function () {
        fetch('/api/live-stats')
            .then(r => r.json())
            .then(data => {
                if (document.getElementById('live-uptime')) document.getElementById('live-uptime').innerText = data.uptime;
                if (document.getElementById('live-cpu-text')) document.getElementById('live-cpu-text').innerText = '%' + data.cpu;
                if (document.getElementById('live-ram-text')) document.getElementById('live-ram-text').innerText = '%' + data.ram;

            })
            .catch(e => console.log('Live stats error:', e));
    }, 2000);

    initCharts();
});

function initCharts() {
    const data = window.DashboardData || {};

    const ctxVol = document.getElementById('volumeChart');
    if (ctxVol && data.volumeLabels) {
        new Chart(ctxVol.getContext('2d'), {
            type: 'bar',
            data: {
                labels: data.volumeLabels,
                datasets: [{
                    label: 'Logs',
                    data: data.volumeData,
                    backgroundColor: '#4f46e5',
                    borderRadius: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { display: false },
                    y: { display: true, grid: { color: '#1b213b' } }
                }
            }
        });
    }
}

// dashboard.js içindeki formatDetails fonksiyonunu bununla değiştir:

function formatDetails(rawText) {
    if (!rawText) return '<div class="text-muted p-3">No details available.</div>';

    let diffContent = "";
    let metaText = rawText;

    // Diff ayrıştırma
    if (rawText.includes("---DIFF START---")) {
        const parts = rawText.split("---DIFF START---");
        metaText = parts[0];
        if (parts[1]) diffContent = parts[1].split("---DIFF END---")[0].trim();
    }

    // Satır satır parse etme (Key: Value)
    const lines = metaText.split('\n').filter(line => line.trim() !== '');
    let data = { raw: rawText }; // Ham veriyi sakla

    lines.forEach(line => {
        const idx = line.indexOf(':');
        if (idx === -1) return;

        // Key'leri standartlaştır (Boşlukları sil, küçük harfe çevir)
        const key = line.substring(0, idx).trim().toUpperCase().replace(/\s+/g, '_');
        const val = line.substring(idx + 1).trim();

        // Veri haritalama (Backend'den gelen isimleri JS objesine çeviriyoruz)
        if (key.includes('EVENT_TYPE')) data.eventType = val;
        else if (key === 'USER' || key === 'ACTOR_USER') data.user = val;
        else if (key === 'UID') data.uid = val;
        else if (key === 'GID') data.gid = val;
        else if (key === 'PID' || key === 'ACTOR_PROCESS') data.pid = val;
        else if (key === 'PPID') data.ppid = val;
        else if (key === 'COMMAND' || key === 'EXECUTED_COMMAND') data.command = val;
        else if (key === 'BINARY') data.binary = val;
        else if (key === 'SOURCE_IP' || key === 'SRC') data.srcIp = val;
        else if (key === 'DESTINATION_IP' || key === 'DST') data.dstIp = val;
        else if (key === 'PORT' || key === 'DPT') data.port = val;
        else if (key === 'PROTOCOL' || key === 'PROTO') data.protocol = val;
        else if (key.includes('ORIGINAL_PATH')) data.origPath = val;
        else if (key.includes('NEW_PATH')) data.newPath = val;
        else if (key.includes('INODE')) data.inode = val;
        else if (key.includes('OLD_PERMISSIONS')) data.oldPerms = val;
        else if (key.includes('NEW_PERMISSIONS')) data.newPerms = val;
        else if (key.includes('OLD_HASH')) data.oldHash = val;
        else if (key.includes('NEW_HASH')) data.newHash = val;
        else if (key.includes('MITRE')) data.mitre = val;
        else if (key.includes('SUSPICION')) data.suspicion = val;
        else if (key.includes('ANALYSIS')) data.analysis = val;
        else if (key.includes('ATTEMPT_COUNT')) data.attempts = val;
    });

    if (data.origPath || data.eventType?.includes('FIM')) {
        return renderFimLayout(data, diffContent);
    }
    else if (data.srcIp || data.eventType?.includes('SSH') || data.eventType?.includes('NET')) {
        return renderNetworkLayout(data);
    }
    else if (data.command || data.binary || data.eventType?.includes('EXEC') || data.eventType?.includes('SUDO')) {
        return renderProcessLayout(data);
    }
    else {
        return renderGenericLayout(data, rawText);
    }
}
function formatDiffLines(diffText) {
    return diffText.split('\n').map(line => {
        const safeLine = line.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        if (line.startsWith('---') || line.startsWith('+++')) return `<div style="color: #8b949e; opacity: 0.7;">${safeLine}</div>`;
        if (line.startsWith('@@')) return `<div style="color: #79c0ff; margin-top:5px; margin-bottom:5px;">${safeLine}</div>`;
        if (line.startsWith('+')) return `<div style="color: #e6ffec; background: rgba(46, 160, 67, 0.15); display:block; width:100%;">${safeLine}</div>`;
        if (line.startsWith('-')) return `<div style="color: #ffebe9; background: rgba(255, 123, 114, 0.15); display:block; width:100%;">${safeLine}</div>`;
        return `<div style="color: #8b949e;">${safeLine}</div>`;
    }).join('');
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

function renderGenericLayout(data, rawText) {
    return `
    <div class="detail-box">
        <h5 class="text-white mb-3 border-bottom border-secondary pb-2 border-opacity-25">Raw Event Details</h5>
        <div class="p-3 rounded text-white font-monospace" style="background: #0d1117; white-space: pre-wrap; word-break: break-all;">${rawText}</div>
    </div>
    `;
}

function renderFimLayout(data, diffContent) {
    const isHashChanged = (data.oldHash && data.newHash && data.oldHash !== data.newHash);

    // Hash Bloğu HTML'i (Eski ve Yeni Hash'i gösterir)
    let hashBlock = '';
    if (data.oldHash || data.newHash) {
        hashBlock = `
        <div class="p-3 rounded border border-secondary border-opacity-25 mb-4" style="background: #0d1117;">
            <div class="d-flex justify-content-between align-items-center mb-2">
                <span class="text-secondary small fw-bold text-uppercase">Content Hash (SHA256)</span>
                ${isHashChanged ?
                '<span class="badge bg-danger bg-opacity-10 text-danger border border-danger border-opacity-25">MISMATCH</span>' :
                '<span class="badge bg-success bg-opacity-10 text-success border border-success border-opacity-25">VERIFIED</span>'
            }
            </div>
            
            ${isHashChanged ?
                `<!-- Hash Değişmişse: Eski ve Yeni Alt Alta -->
                <div class="d-flex flex-column gap-2">
                    <div class="d-flex align-items-center">
                        <span class="badge bg-danger me-2" style="width: 45px;">OLD</span>
                        <code class="text-danger flex-grow-1 text-break" style="font-size: 0.8em;">${data.oldHash}</code>
                    </div>
                    <div class="d-flex align-items-center">
                        <span class="badge bg-success me-2" style="width: 45px;">NEW</span>
                        <code class="text-success flex-grow-1 text-break" style="font-size: 0.8em;">${data.newHash}</code>
                    </div>
                </div>`
                :
                `<!-- Hash Aynıysa: Tek Satır -->
                <div class="d-flex align-items-center">
                    <span class="badge bg-secondary me-2" style="width: 45px;">CUR</span>
                    <code class="text-muted flex-grow-1 text-break" style="font-size: 0.8em;">${data.newHash || data.oldHash}</code>
                </div>`
            }
        </div>`;
    }

    return `
    <div class="detail-box" style="font-family: 'Inter', sans-serif;">
        <!-- Header -->
        <div class="d-flex align-items-center mb-4">
            <div class="me-3 p-3 rounded bg-primary bg-opacity-10 text-primary">
                <i class="fas fa-file-contract fa-lg"></i>
            </div>
            <div>
                <h4 class="fw-bold text-white mb-0">${data.eventType}</h4>
                <div class="text-secondary small">${data.analysis}</div>
            </div>
        </div>

        <!-- Path Operations -->
        <div class="p-3 rounded border border-secondary border-opacity-25 mb-4" style="background: #0d1117;">
            <div class="row align-items-center">
                <div class="col-md-5 text-break font-monospace text-secondary">${data.origPath}</div>
                <div class="col-md-2 text-center text-muted"><i class="fas fa-arrow-right"></i></div>
                <div class="col-md-5 text-break font-monospace text-white fw-bold">${data.newPath || data.origPath}</div>
            </div>
        </div>

        <!-- Metadata Grid -->
        <div class="row g-3 mb-4">
            <div class="col-md-4">
                <div class="p-2 border-start border-3 border-secondary ps-3">
                    <div class="text-muted small text-uppercase">UID / GID</div>
                    <div class="text-white">${data.uid || '-'} / ${data.gid || '-'}</div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="p-2 border-start border-3 border-info ps-3">
                    <div class="text-muted small text-uppercase">Inode</div>
                    <div class="text-white">${data.inode || '-'}</div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="p-2 border-start border-3 border-warning ps-3">
                    <div class="text-muted small text-uppercase">Permissions</div>
                    <div class="text-white">
                        ${data.oldPerms || ''} ${data.oldPerms ? '→' : ''} <span class="text-warning">${data.newPerms || '-'}</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- HASH BLOCK (Buraya eklendi) -->
        ${hashBlock}

        <!-- Diff Viewer -->
        ${diffContent ? `
        <div class="mt-2">
            <div class="d-flex justify-content-between align-items-center mb-2">
                <span class="text-secondary small fw-bold text-uppercase">Content Changes</span>
                <span class="badge bg-dark border border-secondary text-secondary">Diff View</span>
            </div>
            <div class="custom-scroll p-3 rounded" style="background: #0d1117; border: 1px solid #30363d; max-height: 400px; overflow-y: auto; font-family: 'Consolas', monospace; font-size: 0.85rem;">
                ${formatDiffLines(diffContent)}
            </div>
        </div>` : ''}
    </div>
    `;
}

function renderSystemLayout(data) {
    let html = `<div class="detail-box" style="font-family: 'Inter', sans-serif;">`;

    html += `
        <div class="mb-4">
             <div class="d-flex align-items-baseline">
                 <h4 class="fw-bold text-white mb-0 me-2" style="letter-spacing: -0.5px;">
                     ${data.analysis.replace(/\.$/, '')}
                 </h4>
                 <span class="text-secondary font-monospace" style="font-size: 0.9rem;">(${data.eventType})</span>
             </div>
        </div>
    `;

    html += `<div class="d-flex flex-wrap border border-secondary border-opacity-25 rounded mb-4" style="background-color: #0d1117; overflow: hidden;">`;

    const makeCell = (label, content) => {
        if (!content) return '';
        return `<div class="p-3 border-end border-secondary border-opacity-25" style="flex: 1; min-width: 120px;">
            <div class="text-secondary small text-uppercase fw-bold mb-2" style="font-size: 0.65rem;">${label}</div>
            <div class="font-monospace text-white" style="font-size: 0.9rem;">${content}</div>
        </div>`;
    };

    if (data.user) html += makeCell('User', data.user);
    if (data.sourceIp) html += makeCell('Source IP', data.sourceIp);
    if (data.protocol) html += makeCell('Protocol', data.protocol);
    if (data.pid) html += makeCell('PID', data.pid);

    html += `</div>`;

    if (data.command) {
        html += `
        <div class="mb-3 px-3 py-3 rounded border border-secondary border-opacity-10" style="background: #0d1117;">
            <div class="text-secondary small text-uppercase fw-bold mb-2" style="font-size: 0.65rem;">Executed Command</div>
            <div class="font-monospace text-warning" style="font-size: 0.9rem; word-break: break-all;">
                 $ ${data.command}
            </div>
        </div>`;
    }

    html += `</div>`;
    return html;
}

function renderProcessLayout(data) {
    return `
    <div class="detail-box" style="font-family: 'Inter', sans-serif;">
        <!-- Header: Event Tipi ve MITRE -->
        <div class="d-flex justify-content-between align-items-start mb-4">
            <div>
                <div class="text-secondary small fw-bold text-uppercase mb-1">Execution Event</div>
                <h4 class="fw-bold text-white mb-0">${data.eventType || 'UNKNOWN EXECUTION'}</h4>
            </div>
            ${data.mitre ? `<span class="badge bg-danger bg-opacity-10 text-danger border border-danger border-opacity-25 px-3 py-2">${data.mitre}</span>` : ''}
        </div>

        <!-- User Context Cards -->
        <div class="row g-3 mb-4">
            <div class="col-md-4">
                <div class="p-3 rounded border border-secondary border-opacity-25" style="background: rgba(255,255,255,0.02);">
                    <div class="d-flex align-items-center mb-2">
                        <i class="fas fa-user text-primary me-2"></i>
                        <span class="text-secondary small fw-bold">USER / UID</span>
                    </div>
                    <div class="font-monospace text-white">${data.user || 'N/A'} <span class="text-muted small">(${data.uid || '-'})</span></div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="p-3 rounded border border-secondary border-opacity-25" style="background: rgba(255,255,255,0.02);">
                    <div class="d-flex align-items-center mb-2">
                        <i class="fas fa-microchip text-warning me-2"></i>
                        <span class="text-secondary small fw-bold">PROCESS ID</span>
                    </div>
                    <div class="font-monospace text-white">${data.pid || 'N/A'}</div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="p-3 rounded border border-secondary border-opacity-25" style="background: rgba(255,255,255,0.02);">
                    <div class="d-flex align-items-center mb-2">
                        <i class="fas fa-terminal text-info me-2"></i>
                        <span class="text-secondary small fw-bold">BINARY</span>
                    </div>
                    <div class="font-monospace text-white text-truncate">${data.binary || 'N/A'}</div>
                </div>
            </div>
        </div>

        <!-- Terminal Window For Command -->
        <div class="mb-4">
            <div class="text-secondary small fw-bold mb-2 text-uppercase">Executed Command Line</div>
            <div class="p-3 rounded position-relative" style="background-color: #0f172a; border: 1px solid #334155; font-family: 'Consolas', monospace;">
                <div class="d-flex gap-2 mb-3 border-bottom border-secondary border-opacity-10 pb-2">
                    <span style="width:10px; height:10px; background:#ef4444; border-radius:50%;"></span>
                    <span style="width:10px; height:10px; background:#f59e0b; border-radius:50%;"></span>
                    <span style="width:10px; height:10px; background:#22c55e; border-radius:50%;"></span>
                </div>
                <div style="color: #4ade80; word-break: break-all;">
                    <span class="text-secondary me-2">$</span>${data.command || 'No command captured'}
                </div>
            </div>
        </div>

        <!-- Suspicion / Analysis Note -->
        ${data.suspicion || data.analysis ? `
        <div class="alert border-0 d-flex align-items-start" style="background: rgba(239, 68, 68, 0.1); color: #fca5a5;">
            <i class="fas fa-exclamation-triangle mt-1 me-3"></i>
            <div>
                <strong class="d-block mb-1 text-uppercase small">Analysis Report</strong>
                ${data.suspicion || data.analysis}
            </div>
        </div>` : ''}
    </div>
    `;
}

function renderNetworkLayout(data) {
    const isSSH = data.eventType?.includes('SSH');
    const icon = isSSH ? 'fa-key' : 'fa-network-wired';
    const colorClass = isSSH ? 'text-warning' : 'text-info';

    return `
    <div class="detail-box" style="font-family: 'Inter', sans-serif;">
        
        <!-- Header -->
        <div class="d-flex align-items-center mb-5">
            <div class="me-3 p-3 rounded-circle" style="background: rgba(255,255,255,0.05);">
                <i class="fas ${icon} fa-2x ${colorClass}"></i>
            </div>
            <div>
                <div class="text-secondary small fw-bold text-uppercase">Network Event</div>
                <h3 class="fw-bold text-white mb-0">${data.eventType}</h3>
                <div class="text-muted small">${data.analysis || 'Traffic analysis detected'}</div>
            </div>
        </div>

        <!-- Connection Flow Visualizer -->
        <div class="d-flex align-items-center justify-content-between p-4 rounded mb-4 position-relative" 
             style="background: #0d1117; border: 1px solid #30363d;">
            
            <!-- Source (Attacker) -->
            <div class="text-center" style="z-index: 2;">
                <div class="text-secondary small fw-bold mb-2">SOURCE</div>
                <div class="fs-5 fw-bold text-white mb-1">${data.srcIp || 'Unknown'}</div>
                ${data.user ? `<span class="badge bg-secondary bg-opacity-25 text-light"><i class="fas fa-user me-1"></i> ${data.user}</span>` : ''}
            </div>

            <!-- Arrow & Protocol -->
            <div class="flex-grow-1 mx-4 text-center position-relative">
                <div style="height: 2px; background: #30363d; position: absolute; top: 50%; width: 100%; z-index: 1;"></div>
                <div class="position-relative bg-dark px-3 d-inline-block" style="z-index: 2; border: 1px solid #30363d; border-radius: 20px;">
                    <span class="text-info fw-bold small">${data.protocol || 'TCP'}</span>
                    ${data.port ? `<span class="text-white small ms-1">:${data.port}</span>` : ''}
                </div>
                <i class="fas fa-chevron-right position-absolute text-muted" style="right: 0; top: 50%; transform: translateY(-50%); z-index: 2;"></i>
            </div>

            <!-- Dest (Target) -->
            <div class="text-center" style="z-index: 2;">
                <div class="text-secondary small fw-bold mb-2">TARGET</div>
                <div class="fs-5 fw-bold text-white mb-1">${data.dstIp || 'Server'}</div>
                <span class="badge bg-success bg-opacity-10 text-success">Active System</span>
            </div>
        </div>

        <!-- Extra Details Grid -->
        <div class="row g-3">
            ${data.attempts ? `
            <div class="col-6">
                <div class="p-3 rounded border border-danger border-opacity-25 text-center" style="background: rgba(220, 53, 69, 0.05);">
                    <div class="display-6 fw-bold text-danger">${data.attempts}</div>
                    <div class="text-secondary small text-uppercase">Failed Attempts</div>
                </div>
            </div>` : ''}
            
            ${data.command ? `
            <div class="col-12">
                <div class="p-3 rounded border border-secondary border-opacity-10" style="background: rgba(255,255,255,0.02);">
                    <div class="text-secondary small fw-bold mb-1">ASSOCIATED COMMAND</div>
                    <code class="text-warning">${data.command}</code>
                </div>
            </div>` : ''}
        </div>
    </div>
    `;
}

// --- ÖZEL PLUGIN: Barların Ucuna Sayı Yazdırma ---
const barLabelPlugin = {
    id: 'barLabelPlugin',
    afterDatasetsDraw(chart, args, options) {
        const { ctx } = chart;
        ctx.save();
        ctx.font = "bold 11px 'Inter', sans-serif";
        ctx.fillStyle = '#cbd5e1'; // Açık gri metin rengi
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';

        chart.data.datasets.forEach((dataset, i) => {
            const meta = chart.getDatasetMeta(i);
            meta.data.forEach((bar, index) => {
                const value = dataset.data[index];
                if (value > 0) { // Sadece değeri 0'dan büyükse yaz
                    // Yatay bar olduğu için x pozisyonunun biraz sağına yazıyoruz
                    ctx.fillText(value, bar.x + 5, bar.y);
                }
            });
        });
        ctx.restore();
    }
};

let trafficChartObj = null;
let actionChartObj = null;
let portChartObj = null;
let scanTypeChartObj = null;
let geoChartObj = null;

function initFirewallCharts() {

    const ctxTraffic = document.getElementById('firewallTrafficChart');
    if (ctxTraffic) {
        trafficChartObj = new Chart(ctxTraffic.getContext('2d'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Current Traffic',
                        data: [],
                        borderColor: '#0dcaf0',
                        backgroundColor: (context) => {
                            const ctx = context.chart.ctx;
                            const gradient = ctx.createLinearGradient(0, 0, 0, 300);
                            gradient.addColorStop(0, 'rgba(13, 202, 240, 0.4)');
                            gradient.addColorStop(1, 'rgba(13, 202, 240, 0.0)');
                            return gradient;
                        },
                        borderWidth: 2,
                        tension: 0.4,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6
                    },
                    {
                        label: 'Baseline (Avg)',
                        data: [],
                        borderColor: '#475569',
                        borderDash: [5, 5],
                        borderWidth: 1,
                        tension: 0.4,
                        pointRadius: 0
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: true, labels: { color: '#94a3b8', font: { size: 10 } } },
                    tooltip: { mode: 'index', intersect: false }
                },
                scales: {
                    x: { grid: { display: false }, ticks: { color: '#64748b', font: { size: 10 } } },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#64748b', font: { size: 10 } },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    const ctxScan = document.getElementById('scanTypeChart');
    if (ctxScan) {
        scanTypeChartObj = new Chart(ctxScan.getContext('2d'), {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Events',
                    data: [],
                    backgroundColor: ['#ef4444', '#f59e0b', '#8b5cf6', '#ec4899', '#3b82f6'],
                    borderRadius: 3,
                    barPercentage: 0.6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        display: true,
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#64748b', font: { size: 9 } }
                    },
                    y: {
                        display: true,
                        grid: { display: false },
                        ticks: { color: '#e2e8f0', font: { size: 10, family: 'monospace' } }
                    }
                }
            }
        });
    }

    updateFirewallData();
    setInterval(updateFirewallData, 5000);
}

function updateFirewallData() {
    fetch('/api/firewall_stats')
        .then(r => {
            if (!r.ok) throw new Error("API Erişilemiyor");
            return r.json();
        })
        .then(data => {
            if (trafficChartObj) {
                trafficChartObj.data.labels = data.traffic_labels || [];
                trafficChartObj.data.datasets[0].data = data.traffic_values || [];

                if (data.traffic_baseline) {
                    trafficChartObj.data.datasets[1].data = data.traffic_baseline;
                }
                trafficChartObj.update();
            } else {
                console.warn("⚠️ trafficChartObj bulunamadı. Canvas ID yanlış olabilir.");
            }

            if (scanTypeChartObj && data.scan_types) {
                const labels = Object.keys(data.scan_types).map(l => l.replace(/_/g, ' '));
                const values = Object.values(data.scan_types);

                scanTypeChartObj.data.labels = labels;
                scanTypeChartObj.data.datasets[0].data = values;
                scanTypeChartObj.update();
            }

            if (data.geo_stats && data.actions && data.top_ports) {
                updateCompositionChart(data.geo_stats, data.actions, data.top_ports);
            }

            const tableBody = document.getElementById('offenders-table-body');
            if (tableBody && data.repeated_offenders && data.repeated_offenders.length > 0) {
                tableBody.innerHTML = data.repeated_offenders.map(ip => `
                    <tr>
                        <td class="ps-3 font-monospace text-white">${ip.ip}</td>
                        <td><span class="badge ${ip.type === 'Internal' ? 'bg-primary' : 'bg-danger'} bg-opacity-25 text-white border border-opacity-25">${ip.type}</span></td>
                        <td class="fw-bold text-danger text-center">${ip.count}</td>
                        <td class="text-muted small">${ip.last_seen}</td>
                    </tr>
                `).join('');
            } else if (tableBody) {
                tableBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted small py-3">Henüz veri yok...</td></tr>';
            }
        })
        .catch(err => console.error("❌ Grafik Güncelleme Hatası:", err));
}

document.addEventListener('DOMContentLoaded', initFirewallCharts);

let gaugeChartObj = null;
let bubbleChartObj = null;

function updateCompositionChart(geoData, actionData, portData) {

    const intTotal = geoData['Internal'] || 0;
    const extTotal = geoData['External'] || 0;

    const totalAllowed = actionData['ALLOW'] || 0;
    const totalBlocked = actionData['BLOCK'] || 0;
    const totalDropped = actionData['DROP'] || 0;

    const totalActions = totalAllowed + totalBlocked + totalDropped;

    const allowRate = totalActions > 0 ? (totalAllowed / totalActions) : 0;
    const blockRate = totalActions > 0 ? (totalBlocked / totalActions) : 0;
    const dropRate = totalActions > 0 ? (totalDropped / totalActions) : 0;

    const intAllowed = Math.floor(intTotal * allowRate);
    const intBlocked = Math.floor(intTotal * blockRate);
    const intDropped = Math.max(0, intTotal - intAllowed - intBlocked);

    const extAllowed = Math.floor(extTotal * allowRate);
    const extBlocked = Math.floor(extTotal * blockRate);
    const extDropped = Math.max(0, extTotal - extAllowed - extBlocked);

    const intEl = document.getElementById('int-val');
    const extEl = document.getElementById('ext-val');
    if (intEl) intEl.innerText = intTotal.toLocaleString();
    if (extEl) extEl.innerText = extTotal.toLocaleString();

    if (document.getElementById('int-allow')) document.getElementById('int-allow').innerText = intAllowed.toLocaleString();
    if (document.getElementById('int-block')) document.getElementById('int-block').innerText = intBlocked.toLocaleString();
    if (document.getElementById('int-drop')) document.getElementById('int-drop').innerText = intDropped.toLocaleString();

    if (document.getElementById('ext-allow')) document.getElementById('ext-allow').innerText = extAllowed.toLocaleString();
    if (document.getElementById('ext-block')) document.getElementById('ext-block').innerText = extBlocked.toLocaleString();
    if (document.getElementById('ext-drop')) document.getElementById('ext-drop').innerText = extDropped.toLocaleString();


    const ctxGauge = document.getElementById('gaugeChart');

    const totalStopped = totalBlocked + totalDropped;
    const blockPercent = totalActions > 0 ? Math.round((totalStopped / totalActions) * 100) : 0;

    const gaugeText = document.getElementById('gauge-val');
    if (gaugeText) {
        gaugeText.innerText = `%${blockPercent}`;
        gaugeText.style.color = blockPercent > 50 ? '#ff0055' : '#22c55e';
    }

    if (ctxGauge) {
        if (gaugeChartObj) {
            gaugeChartObj.data.datasets[0].data = [blockPercent, 100 - blockPercent];
            gaugeChartObj.update();
        } else {
            gaugeChartObj = new Chart(ctxGauge.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['Blocked/Dropped', 'Allowed'],
                    datasets: [{
                        data: [blockPercent, 100 - blockPercent],
                        backgroundColor: [
                            '#ff0055',
                            'rgba(255, 255, 255, 0.05)'
                        ],
                        borderWidth: 0,
                        cutout: '85%',
                        circumference: 180,
                        rotation: -90,
                        borderRadius: 10
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false }, tooltip: { enabled: false } }
                }
            });
        }
    }

    const ctxBubble = document.getElementById('bubbleTargetsChart');

    let bubbleData = [];
    if (portData && portData.length > 0) {
        const maxHits = Math.max(...portData.map(p => p.count));

        bubbleData = portData.map((port, index) => {
            const size = 5 + ((port.count / maxHits) * 15);
            return {
                x: index * 15,
                y: port.count,
                r: size,
                port: port.dst_port,
                hits: port.count
            };
        });
    }

    if (ctxBubble) {
        if (bubbleChartObj) {
            bubbleChartObj.data.datasets[0].data = bubbleData;
            bubbleChartObj.update();
        } else {
            bubbleChartObj = new Chart(ctxBubble.getContext('2d'), {
                type: 'bubble',
                data: {
                    datasets: [{
                        label: 'Targets',
                        data: bubbleData,
                        backgroundColor: (context) => {
                            const val = context.raw?.hits || 0;
                            return val > 50 ? 'rgba(255, 0, 85, 0.8)' : 'rgba(255, 193, 7, 0.8)';
                        },
                        borderColor: (context) => {
                            const val = context.raw?.hits || 0;
                            return val > 50 ? '#ff0055' : '#ffc107';
                        },
                        borderWidth: 1,
                        hoverBackgroundColor: '#ffffff',
                        hoverRadius: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: 'rgba(15, 23, 42, 0.95)',
                            titleColor: '#fff',
                            bodyColor: '#cbd5e1',
                            displayColors: false,
                            callbacks: {
                                label: function (context) {
                                    const raw = context.raw;
                                    return ` Port: ${raw.port} | Hits: ${raw.hits}`;
                                }
                            }
                        }
                    },
                    scales: {
                        x: { display: false, min: -10, max: (portData.length * 15) + 10 },
                        y: { display: false, min: 0 }
                    },
                    layout: { padding: 10 }
                }
            });
        }
    }
}