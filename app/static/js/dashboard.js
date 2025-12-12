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

// dashboard.js

// Global değişken: Hangi alarmı kapatıyoruz?
let targetAlertId = null;
let resolveModalObj = null;

// 1. Butona basılınca Modalı Açan Fonksiyon
function resolveAlert(alertId) {
    targetAlertId = alertId;

    // Inputu temizle
    document.getElementById('resolveNote').value = '';
    document.getElementById('resolveAlertId').value = alertId;

    // Modalı göster
    const modalEl = document.getElementById('resolveModal');
    if (modalEl) {
        resolveModalObj = new bootstrap.Modal(modalEl);
        resolveModalObj.show();
    }
}

// 2. Modaldaki "Confirm" butonuna basılınca çalışan fonksiyon
function confirmResolution() {
    if (!targetAlertId) return;

    const note = document.getElementById('resolveNote').value;
    const finalNote = note.trim() === '' ? 'Hızlı kapatma (Not girilmedi)' : note;

    // API İsteği
    fetch(`/api/resolve_alert/${targetAlertId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: finalNote }) // Notu da gönderiyoruz
    })
        .then(response => {
            if (response.ok) {
                // Modalı gizle
                if (resolveModalObj) resolveModalObj.hide();

                // Kartı animasyonla sil
                const card = document.getElementById(`alert-card-${targetAlertId}`);
                if (card) {
                    card.style.transition = "all 0.5s ease";
                    card.style.transform = "translateX(50px)";
                    card.style.opacity = "0";
                }

                // Sayfayı yenile (Puan güncellensin diye)
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

// 2. Diğer DOM işlemleri burada kalabilir
document.addEventListener('DOMContentLoaded', function () {

    // Tema ayarları vs.
    const html = document.documentElement;
    if (!localStorage.getItem('theme')) {
        localStorage.setItem('theme', 'dark');
        html.setAttribute('data-bs-theme', 'dark');
    } else {
        html.setAttribute('data-bs-theme', localStorage.getItem('theme'));
    }

    // Canlı istatistikleri çekme (setInterval)
    setInterval(function () {
        fetch('/api/live-stats')
            .then(r => r.json())
            .then(data => {
                // Uptime, CPU, RAM güncellemeleri
                if (document.getElementById('live-uptime')) document.getElementById('live-uptime').innerText = data.uptime;
                if (document.getElementById('live-cpu-text')) document.getElementById('live-cpu-text').innerText = '%' + data.cpu;
                if (document.getElementById('live-ram-text')) document.getElementById('live-ram-text').innerText = '%' + data.ram;

                // Process listesi güncelleme (Varsa kodlarını buraya ekle)
            })
            .catch(e => console.log('Live stats error:', e));
    }, 2000); // 2 saniyede bir güncelle

    // Grafiklerin çizimi (Chart.js kodları buradaysa buraya gelecek)
    initCharts();
});

// Grafikleri başlatan yardımcı fonksiyon (Kodun temiz kalsın diye ayırdım)
function initCharts() {
    const data = window.DashboardData || {};

    // Volume Chart
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

function formatDetails(rawText) {
    if (!rawText) return '<div class="text-muted p-3">No details available.</div>';

    let diffContent = "";
    let metaText = rawText;

    if (rawText.includes("---DIFF START---")) {
        const parts = rawText.split("---DIFF START---");
        metaText = parts[0];
        if (parts[1]) diffContent = parts[1].split("---DIFF END---")[0].trim();
    }

    const lines = metaText.split('\n').filter(line => line.trim() !== '');

    let data = {
        eventType: 'UNKNOWN',
        origPath: '', newPath: '', inode: '',
        uid: '', gid: '',
        oldPerms: '', newPerms: '',
        oldHash: '', newHash: '',
        analysis: 'Anomaly Detected',
        user: '', sourceIp: '', command: '', pid: '', protocol: '', binary: ''
    };

    lines.forEach(line => {
        const idx = line.indexOf(':');
        if (idx === -1) return;
        const key = line.substring(0, idx).trim().toUpperCase();
        const val = line.substring(idx + 1).trim();

        if (key.includes('EVENT TYPE')) data.eventType = val;
        else if (key.includes('ORIGINAL PATH')) data.origPath = val;
        else if (key.includes('NEW PATH')) data.newPath = val;
        else if (key.includes('OLD INODE')) data.oldInode = val;
        else if (key.includes('NEW INODE')) data.newInode = val;
        else if (key.includes('INODE')) data.inode = val;
        else if (key === 'UID') data.uid = val;
        else if (key === 'GID') data.gid = val;
        else if (key.includes('OLD PERMISSIONS')) data.oldPerms = val;
        else if (key.includes('NEW PERMISSIONS')) data.newPerms = val;
        else if (key.includes('OLD HASH')) data.oldHash = val;
        else if (key.includes('NEW HASH')) data.newHash = val;
        else if (key.includes('ANALYSIS')) data.analysis = val;
        else if (key === 'USER') data.user = val;
        else if (key === 'SOURCE IP') data.sourceIp = val;
        else if (key === 'COMMAND') data.command = val;
        else if (key === 'PID') data.pid = val;
        else if (key === 'PROTOCOL') data.protocol = val;

    });

    if (data.origPath) {
        return renderFimLayout(data, diffContent);
    }
    else if (data.user || data.sourceIp || data.command) {
        return renderSystemLayout(data);
    }
    else {
        return `<div class="p-3 text-white">${rawText.replace(/\n/g, '<br>')}</div>`;
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

function renderFimLayout(data, diffContent) {
    const isPermChanged = (data.oldPerms && data.newPerms && data.oldPerms !== data.newPerms);
    const isHashChanged = (data.oldHash && data.newHash && data.oldHash !== data.newHash);

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
    const makeCell = (label, content, isLast = false) => {
        return `<div class="p-3 ${isLast ? '' : 'border-end border-secondary border-opacity-25'}" style="flex: 1; min-width: 100px;">
            <div class="text-secondary small text-uppercase fw-bold mb-2" style="font-size: 0.65rem;">${label}</div>
            <div class="font-monospace text-white d-flex align-items-center" style="font-size: 0.9rem;">${content || 'N/A'}</div>
        </div>`;
    };

    html += makeCell('UID', data.uid);

    html += makeCell('GID', data.gid);

    let inodeContent = data.inode || 'N/A';
    if (data.oldInode && data.newInode && data.oldInode !== data.newInode) {
        inodeContent = `
                <span style="color: #3fb950; background: rgba(63, 185, 80, 0.15); padding: 2px 6px; border-radius: 4px; font-weight: bold; border: 1px solid rgba(63, 185, 80, 0.2);">
                    ${data.oldInode}
                </span> 
                <i class="fas fa-arrow-right mx-2 text-muted" style="font-size: 0.8em;"></i> 
                <span style="color: #ff7b72; background: rgba(255, 123, 114, 0.15); padding: 2px 6px; border-radius: 4px; font-weight: bold; border: 1px solid rgba(255, 123, 114, 0.2);">
                    ${data.newInode}
                </span>
            `;
    }

    html += makeCell('Inode', inodeContent);
    let permContent = isPermChanged ?
        `<span style="color:#3fb950; background: rgba(63,185,80,0.15); padding: 0 4px; border-radius: 3px; border: 1px solid rgba(63, 185, 80, 0.2);">${data.oldPerms}</span> 
         <i class="fas fa-arrow-right mx-2 text-muted" style="font-size: 0.7em;"></i> 
         <span style="color:#ff7b72; background: rgba(255,123,114,0.15); padding: 0 4px; border-radius: 3px; border: 1px solid rgba(255, 123, 114, 0.2);">${data.newPerms}</span>` :
        `<span class="text-white">${data.newPerms || data.oldPerms || 'N/A'}</span>`;

    html += makeCell('Permissions', permContent, true);
    html += `</div>`;

    html += `
    <div class="mb-3 px-3 py-3 rounded border border-secondary border-opacity-10" style="background: #0d1117;">
        <div class="text-secondary small text-uppercase fw-bold mb-2" style="font-size: 0.65rem;">Path Operations</div>
        <div class="font-monospace" style="font-size: 0.9rem; color: #e6edf3; word-break: break-all;">
             ${data.newPath ?
            `<span style="color:#ff7b72;">${data.origPath}</span> <i class="fas fa-arrow-right mx-2 text-muted"></i> <span style="color:#3fb950;">${data.newPath}</span>`
            : `<span style="color:#e6edf3;">${data.origPath}</span>`}
        </div>
    </div>`;

    if (data.oldHash || data.newHash) {
        html += `
        <div class="mb-3 px-3 py-3 rounded border border-secondary border-opacity-10" style="background: #0d1117;">
             <div class="text-secondary small text-uppercase fw-bold mb-2" style="font-size: 0.65rem;">Content Hash (SHA256)</div>
             ${isHashChanged ?
                `<div class="font-monospace small mb-1" style="color: #ff7b72;">- ${data.oldHash}</div>
                 <div class="font-monospace small" style="color: #3fb950;">+ ${data.newHash}</div>` :
                `<div class="font-monospace small text-muted">${data.newHash || data.oldHash} <span class="ms-2 opacity-50 fst-italic">(Unchanged)</span></div>`
            }
        </div>`;
    }

    if (diffContent) {
        html += `
        <div class="mt-4">
            <div class="d-flex justify-content-between align-items-end mb-2">
                <div class="text-secondary small text-uppercase fw-bold" style="font-size: 0.65rem;">Content Changes</div>
                
                <!-- LEGEND BURAYA TAŞINDI: Sadece Diff varsa görünür -->
                <div style="font-size: 0.65rem; font-family: monospace;">
                    <span style="color: #3fb950;">+ Added</span>
                    <span class="mx-2 text-secondary opacity-25">|</span>
                    <span style="color: #ff7b72;">- Removed</span>
                </div>
            </div>

            <!-- Kod Bloğu -->
            <div class="custom-scroll p-3 rounded" style="background: #0d1117; border: 1px solid #30363d; max-height: 400px; overflow-y: auto; font-family: 'Consolas', monospace; font-size: 0.85rem;">
                ${formatDiffLines(diffContent)}
            </div>
        </div>`;
    }

    html += `</div>`;
    return html;
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