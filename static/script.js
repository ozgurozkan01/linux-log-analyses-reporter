const circles = {
    cpu: document.getElementById('cpu-circle'),
    ram: document.getElementById('ram-circle'),
    disk: document.getElementById('disk-circle')
};

const colors = {
    cpu: {
        start: getComputedStyle(document.documentElement).getPropertyValue('--cpu-color-start').trim(),
        end: getComputedStyle(document.documentElement).getPropertyValue('--cpu-color-end').trim()
    },
    ram: {
        start: getComputedStyle(document.documentElement).getPropertyValue('--ram-color-start').trim(),
        end: getComputedStyle(document.documentElement).getPropertyValue('--ram-color-end').trim()
    },
    disk: {
        start: getComputedStyle(document.documentElement).getPropertyValue('--disk-color-start').trim(),
        end: getComputedStyle(document.documentElement).getPropertyValue('--disk-color-end').trim()
    }
};

function apply3DStroke(circle, id, startColor, endColor) {
    let svg = circle.closest('svg');
    let defs = svg.querySelector('defs');
    if (!defs) {
        defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
        svg.prepend(defs);
    }

    let existing = defs.querySelector(`#${id}`);
    if (existing) existing.remove();

    let grad = document.createElementNS("http://www.w3.org/2000/svg", "linearGradient");
    grad.id = id;
    grad.setAttribute("x1", "0%");
    grad.setAttribute("y1", "0%");
    grad.setAttribute("x2", "0%");
    grad.setAttribute("y2", "100%");

    let stop1 = document.createElementNS("http://www.w3.org/2000/svg", "stop");
    stop1.setAttribute("offset", "0%");
    stop1.setAttribute("stop-color", startColor);

    let stop2 = document.createElementNS("http://www.w3.org/2000/svg", "stop");
    stop2.setAttribute("offset", "100%");
    stop2.setAttribute("stop-color", endColor);

    grad.appendChild(stop1);
    grad.appendChild(stop2);
    defs.appendChild(grad);

    circle.setAttribute("stroke", `url(#${id})`);
}

apply3DStroke(circles.cpu, 'cpuGrad', colors.cpu.start, colors.cpu.end);
apply3DStroke(circles.ram, 'ramGrad', colors.ram.start, colors.ram.end);
apply3DStroke(circles.disk, 'diskGrad', colors.disk.start, colors.disk.end);

const radius = circles.cpu.r.baseVal.value;
const circumference = 2 * Math.PI * radius;
const GAP_ANGLE = 90;
const ARC_ANGLE = 360 - GAP_ANGLE;
const arcLength = (ARC_ANGLE / 360) * circumference;

Object.values(circles).forEach(circle => {
    const track = circle.previousElementSibling;
    [track, circle].forEach(el => {
        el.style.strokeDasharray = `${arcLength} ${circumference}`;
    });
});

function setProgress(circleElement, percent) {
    const clampedPercent = Math.max(0, Math.min(100, percent));
    const offset = arcLength - (clampedPercent / 100) * arcLength;
    circleElement.style.strokeDashoffset = offset;
}

async function updateStats() {
    try {
        const response = await fetch('/system_stats');
        const stats = await response.json();

        setProgress(circles.cpu, stats.cpu_percent);
        document.getElementById('cpu-percent-text').textContent = `${Math.round(stats.cpu_percent)}%`;

        setProgress(circles.ram, stats.ram_percent);
        document.getElementById('ram-percent-text').textContent = `${Math.round(stats.ram_percent)}%`;
        document.getElementById('ram-usage-text').textContent = `${stats.ram_used_gb.toFixed(1)} / ${stats.ram_total_gb.toFixed(1)}GB`;

        setProgress(circles.disk, stats.disk_percent);
        document.getElementById('disk-percent-text').textContent = `${Math.round(stats.disk_percent)}%`;
        document.getElementById('disk-usage-text').textContent = `${stats.disk_used_gb.toFixed(0)} / ${stats.disk_total_gb.toFixed(0)}GB`;

    } catch (error) {
        console.error("Veriler güncellenirken hata oluştu:", error);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    updateStats();
    setInterval(updateStats, 2000);
});
