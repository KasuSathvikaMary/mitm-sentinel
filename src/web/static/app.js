// MITM Sentinel Frontend Controller
let ws = null;
let packets = [];
let alerts = [];

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        const badge = document.getElementById('ws-status');
        badge.innerHTML = '<span class="dot"></span> MONITORING';
        badge.style.color = '#10b981';
    };

    ws.onclose = () => {
        const badge = document.getElementById('ws-status');
        badge.innerHTML = '<span class="dot" style="background:#ef4444;box-shadow:0 0 8px #ef4444;"></span> DISCONNECTED';
        badge.style.color = '#ef4444';
        setTimeout(connectWebSocket, 2000);
    };

    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleIncomingEvent(msg);
        } catch (e) {
            console.error('Error parsing event:', e);
        }
    };
}

function handleIncomingEvent(event) {
    if (event.event_type === 'SNAPSHOT') {
        const data = event.data;
        updateBaseline(data.state);
        updateMetrics(data.state.metrics);
        updateQuarantine(data.state.quarantined_attackers);
        if (data.alerts) {
            data.alerts.forEach(addAlertToDOM);
        }
        updateDefenseButton(data.auto_remediate);
    } else if (event.event_type === 'PACKET') {
        addPacketToTable(event.data);
        bumpMetric('val-packets');
    } else if (event.event_type === 'ALERT') {
        addAlertToDOM(event.data);
        bumpMetric('val-attacks');
    } else if (event.event_type === 'DEFENSE') {
        bumpMetric('val-defenses');
        annotateLastAlertDefense(event.data);
    }
}

function updateBaseline(state) {
    if (!state) return;
    document.getElementById('base-iface').innerText = state.interface || 'en0';
    document.getElementById('base-local-ip').innerText = state.local_ip || '127.0.0.1';
    document.getElementById('base-gw-ip').innerText = state.gateway_ip || '192.168.1.1';
    document.getElementById('base-gw-mac').innerText = state.baseline_gateway_mac || 'Pending baseline';
}

function updateMetrics(metrics) {
    if (!metrics) return;
    document.getElementById('val-packets').innerText = metrics.packets_analyzed || 0;
    document.getElementById('val-attacks').innerText = metrics.attacks_detected || 0;
    document.getElementById('val-defenses').innerText = metrics.defenses_triggered || 0;
    document.getElementById('val-quarantined').innerText = metrics.threats_blocked || 0;
}

function bumpMetric(elementId) {
    const el = document.getElementById(elementId);
    if (el) {
        let val = parseInt(el.innerText, 10) || 0;
        el.innerText = val + 1;
    }
}

function updateQuarantine(quarantined) {
    const list = document.getElementById('quarantine-list');
    if (!quarantined || Object.keys(quarantined).length === 0) {
        list.innerHTML = '<li class="empty-li">No hosts currently quarantined.</li>';
        return;
    }
    list.innerHTML = '';
    for (const [mac, info] of Object.entries(quarantined)) {
        const li = document.createElement('li');
        li.innerText = `${mac} (${info.ip || 'Unknown'}) - [BLOCKED]`;
        list.appendChild(li);
    }
}

function addAlertToDOM(alert) {
    const container = document.getElementById('alerts-container');
    const empty = container.querySelector('.empty-state');
    if (empty) empty.remove();

    const alertDiv = document.createElement('div');
    alertDiv.className = `alert-item ${alert.severity}`;

    const dateStr = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();

    alertDiv.innerHTML = `
        <div class="alert-top">
            <span class="alert-title">[${alert.severity}] ${alert.threat_type}</span>
            <span class="alert-time">${dateStr}</span>
        </div>
        <div class="alert-desc">${alert.description}</div>
        <div class="alert-meta">
            <span>Attacker: ${alert.attacker_ip || 'N/A'} (${alert.attacker_mac || 'N/A'})</span>
            <span>Target: ${alert.victim_ip || 'Local Host'}</span>
        </div>
        <div class="defense-badge">🛡️ Countermeasure: ${alert.recommended_action || 'Quarantine Enforced'}</div>
    `;

    container.prepend(alertDiv);

    // Update alert count badge
    alerts.push(alert);
    document.getElementById('alerts-count').innerText = `${alerts.length} Events`;

    // Also update quarantined list if attacker MAC is present
    if (alert.attacker_mac) {
        bumpMetric('val-quarantined');
        const list = document.getElementById('quarantine-list');
        const emptyLi = list.querySelector('.empty-li');
        if (emptyLi) emptyLi.remove();

        const li = document.createElement('li');
        li.innerText = `${alert.attacker_mac} (${alert.attacker_ip || 'IP'}) - [BLOCKED]`;
        list.prepend(li);
    }
}

function annotateLastAlertDefense(defenseResult) {
    const firstAlert = document.querySelector('.alert-item');
    if (firstAlert) {
        const dBadge = firstAlert.querySelector('.defense-badge');
        if (dBadge) {
            dBadge.innerText = `🛡️ ${defenseResult.action_name}: ${defenseResult.message}`;
            dBadge.style.color = '#38bdf8';
        }
    }
}

function addPacketToTable(packet) {
    const tbody = document.getElementById('packet-tbody');
    if (tbody.querySelector('.text-center')) {
        tbody.innerHTML = '';
    }

    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td><span style="color:#06b6d4;font-weight:600;">${packet.type || 'RAW'}</span></td>
        <td>${packet.src_ip || packet.src_mac || '--'}</td>
        <td>${packet.dst_ip || packet.dst_mac || '--'}</td>
        <td style="color:#9ca3af;font-size:11px;">${packet.summary || 'Packet captured'}</td>
    `;

    tbody.prepend(tr);
    if (tbody.children.length > 50) {
        tbody.removeChild(tbody.lastChild);
    }
}

function updateDefenseButton(active) {
    const btn = document.getElementById('toggle-defense-btn');
    if (active) {
        btn.className = 'toggle-btn active';
        btn.innerText = 'ACTIVE';
    } else {
        btn.className = 'toggle-btn inactive';
        btn.innerText = 'DISABLED';
    }
}

async function triggerSim(attackType) {
    try {
        const resp = await fetch(`/api/simulate/${attackType}`, { method: 'POST' });
        const data = await resp.json();
        console.log('Sim result:', data);
    } catch (e) {
        console.error('Sim error:', e);
    }
}

document.getElementById('toggle-defense-btn').addEventListener('click', async () => {
    try {
        const resp = await fetch('/api/defense/toggle', { method: 'POST' });
        const data = await resp.json();
        updateDefenseButton(data.auto_remediate);
    } catch (e) {
        console.error('Error toggling defense:', e);
    }
});

// Initialize on load
window.addEventListener('DOMContentLoaded', () => {
    connectWebSocket();
});
