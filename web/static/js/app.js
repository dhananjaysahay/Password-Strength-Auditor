// ─── Tab switching ───

function switchTab(tab) {
  ['password', 'network', 'handshake'].forEach(t => {
    document.getElementById(`panel-${t}`).classList.toggle('hidden', t !== tab);
    document.getElementById(`tab-${t}`).className = t === tab
      ? 'tab-active py-3 px-1 text-sm font-medium transition-colors flex items-center gap-2'
      : 'tab-inactive py-3 px-1 text-sm font-medium transition-colors flex items-center gap-2';
  });
  if (tab === 'network' && !networkLoaded) loadNetwork();
  if (tab === 'handshake' && !handshakeLoaded) loadHandshake();
}

// ─── Password visibility toggle ───

let pwVisible = true;
function toggleVisibility() {
  const input = document.getElementById('pw-input');
  pwVisible = !pwVisible;
  input.type = pwVisible ? 'text' : 'password';
  document.getElementById('eye-open').classList.toggle('hidden', !pwVisible);
  document.getElementById('eye-closed').classList.toggle('hidden', pwVisible);
}

// ─── Password analysis ───

let debounceTimer;
const SCORE_COLORS = {
  red: '#f85149', yellow: '#d29922', bright_yellow: '#e3b341',
  green: '#3fb950', bright_green: '#56d364',
};

document.getElementById('pw-input').addEventListener('input', (e) => {
  clearTimeout(debounceTimer);
  const pw = e.target.value;
  if (!pw) {
    document.getElementById('pw-placeholder').classList.remove('hidden');
    document.getElementById('pw-results').classList.add('hidden');
    document.getElementById('score-container').classList.add('hidden');
    document.getElementById('stats-container').classList.add('hidden');
    return;
  }
  debounceTimer = setTimeout(() => analyzePassword(pw), 250);
});

async function analyzePassword(pw) {
  try {
    const res = await fetch('/api/password/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw }),
    });
    const data = await res.json();
    renderPasswordResults(data);
  } catch (err) {
    console.error('Analysis failed:', err);
  }
}

function renderPasswordResults(data) {
  // Show results, hide placeholder
  document.getElementById('pw-placeholder').classList.add('hidden');
  document.getElementById('pw-results').classList.remove('hidden');
  document.getElementById('score-container').classList.remove('hidden');
  document.getElementById('stats-container').classList.remove('hidden');

  // Score ring
  const ring = document.getElementById('score-ring');
  const circumference = 440;
  const offset = circumference - (data.score / 100) * circumference;
  const color = SCORE_COLORS[data.color] || '#8b949e';
  ring.setAttribute('stroke', color);
  ring.setAttribute('stroke-dashoffset', offset);
  document.getElementById('score-value').textContent = data.score;
  document.getElementById('score-value').setAttribute('fill', color);
  document.getElementById('score-label').textContent = data.label;

  // Stats
  document.getElementById('stat-entropy').textContent = data.analysis.entropy + ' bits';
  document.getElementById('stat-length').textContent = data.analysis.length;
  document.getElementById('stat-unique').textContent = `${data.analysis.unique_chars}/${data.analysis.length}`;
  document.getElementById('stat-classes').textContent = `${data.analysis.char_class_count}/4`;

  // Breakdown bars
  const barsContainer = document.getElementById('breakdown-bars');
  barsContainer.innerHTML = data.breakdown.map(b => {
    const isPositive = b.points >= 0;
    const maxVal = b.max || 25;
    const pct = isPositive ? Math.min(100, (b.points / maxVal) * 100) : 100;
    const barColor = isPositive ? 'bg-accent-green' : 'bg-accent-red';
    const pointsText = isPositive ? `+${b.points}` : `${b.points}`;
    const pointsColor = isPositive ? 'text-accent-green' : 'text-accent-red';
    return `
      <div class="fade-in">
        <div class="flex justify-between text-sm mb-1">
          <span class="text-text-secondary">${b.factor}</span>
          <span class="mono ${pointsColor}">${pointsText}</span>
        </div>
        <div class="h-2 bg-bg-tertiary rounded-full overflow-hidden">
          <div class="${barColor} h-full rounded-full transition-all duration-500" style="width:${pct}%"></div>
        </div>
        <div class="text-xs text-text-muted mt-0.5">${b.detail}</div>
      </div>
    `;
  }).join('');

  // Patterns
  const patSec = document.getElementById('patterns-section');
  const patList = document.getElementById('patterns-list');
  if (data.patterns.length) {
    patSec.classList.remove('hidden');
    patList.innerHTML = data.patterns.map(p => {
      const icon = p.severity === 'high' ? '🔴' : '🟡';
      const borderClass = p.severity === 'high' ? 'risk-high' : 'risk-medium';
      return `
        <div class="${borderClass} bg-bg-primary rounded px-3 py-2 fade-in">
          <span class="text-sm">${icon} ${p.description}</span>
        </div>
      `;
    }).join('');
  } else {
    patSec.classList.add('hidden');
  }

  // Breach
  const breachSec = document.getElementById('breach-section');
  if (data.breach.is_breached) {
    breachSec.classList.remove('hidden');
    document.getElementById('breach-msg').textContent = data.breach.message;
  } else {
    breachSec.classList.add('hidden');
  }

  // Suggestions
  document.getElementById('suggestions-list').innerHTML = data.suggestions.map(s => `
    <li class="flex items-start gap-2 text-sm fade-in">
      <span class="text-accent-green mt-0.5">→</span>
      <span class="text-text-secondary">${s}</span>
    </li>
  `).join('');
}

// ─── Network demo ───

let networkLoaded = false;

async function loadNetwork() {
  try {
    const res = await fetch('/api/network/demo');
    const data = await res.json();
    renderNetwork(data);
    networkLoaded = true;
  } catch (err) {
    document.getElementById('network-content').innerHTML =
      '<p class="text-accent-red">Failed to load network data</p>';
  }
}

function renderNetwork(data) {
  const container = document.getElementById('network-content');

  // Summary bar
  const totalDevices = data.devices.length;
  const riskyDevices = data.devices.filter(d => d.risks.length > 0).length;
  const totalPorts = data.devices.reduce((s, d) => s + d.open_ports.length, 0);

  let html = `
    <div class="bg-bg-secondary border border-border-default rounded-lg p-4 mb-2">
      <div class="flex items-center gap-2 text-sm text-text-secondary mb-3">
        <span class="mono text-accent-blue">${data.target}</span>
        <span>·</span>
        <span>${data.note}</span>
      </div>
      <div class="grid grid-cols-3 gap-4">
        <div class="text-center">
          <div class="text-2xl font-bold mono">${totalDevices}</div>
          <div class="text-xs text-text-secondary">Devices Found</div>
        </div>
        <div class="text-center">
          <div class="text-2xl font-bold mono">${totalPorts}</div>
          <div class="text-xs text-text-secondary">Open Ports</div>
        </div>
        <div class="text-center">
          <div class="text-2xl font-bold mono text-accent-red">${riskyDevices}</div>
          <div class="text-xs text-text-secondary">With Risks</div>
        </div>
      </div>
    </div>
  `;

  // Device cards
  html += data.devices.map(dev => {
    const hasRisk = dev.risks.length > 0;
    const borderColor = hasRisk ? 'border-accent-red/30' : 'border-border-default';

    const portsHtml = dev.open_ports.map(p => {
      const isInsecure = data.insecure_ports_reference[String(p.port)];
      return `
        <div class="flex items-center justify-between py-1.5 border-b border-border-default last:border-0">
          <div class="flex items-center gap-2">
            <span class="mono text-sm ${isInsecure ? 'text-accent-red' : 'text-accent-green'}">${p.port}</span>
            <span class="text-sm text-text-secondary">${p.service}</span>
          </div>
          <span class="text-xs text-text-muted mono">${p.version || ''}</span>
        </div>
      `;
    }).join('');

    const risksHtml = dev.risks.map(r => `
      <div class="risk-high bg-accent-red/5 rounded px-3 py-1.5 text-sm text-accent-red">${r}</div>
    `).join('');

    return `
      <div class="bg-bg-secondary border ${borderColor} rounded-lg p-5 fade-in">
        <div class="flex items-start justify-between mb-3">
          <div>
            <div class="font-medium flex items-center gap-2">
              ${dev.hostname || dev.ip}
              ${hasRisk ? '<span class="w-2 h-2 rounded-full bg-accent-red inline-block"></span>' : ''}
            </div>
            <div class="text-sm text-text-muted mono mt-0.5">${dev.ip} · ${dev.mac}</div>
          </div>
          <span class="text-xs bg-bg-tertiary text-text-secondary px-2 py-1 rounded">${dev.vendor}</span>
        </div>
        <div class="mb-3">${portsHtml}</div>
        ${risksHtml ? `<div class="space-y-1.5 mt-3">${risksHtml}</div>` : ''}
      </div>
    `;
  }).join('');

  container.innerHTML = html;
}

// ─── Handshake demo ───

let handshakeLoaded = false;

async function loadHandshake() {
  try {
    const res = await fetch('/api/handshake/demo');
    const data = await res.json();
    renderHandshake(data);
    handshakeLoaded = true;
  } catch (err) {
    document.getElementById('handshake-content').innerHTML =
      '<p class="text-accent-red">Failed to load handshake data</p>';
  }
}

function renderHandshake(data) {
  const container = document.getElementById('handshake-content');
  let html = '';

  // Capture metadata
  html += `
    <div class="bg-bg-secondary border border-border-default rounded-lg p-5">
      <h3 class="text-sm font-semibold mb-3 text-text-secondary uppercase tracking-wider">Capture Metadata</h3>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div>
          <div class="text-xl font-bold mono">${data.capture.total_packets.toLocaleString()}</div>
          <div class="text-xs text-text-secondary">Total Packets</div>
        </div>
        <div>
          <div class="text-xl font-bold mono">${data.capture.dot11_packets.toLocaleString()}</div>
          <div class="text-xs text-text-secondary">802.11 Frames</div>
        </div>
        <div>
          <div class="text-xl font-bold mono text-accent-blue">${data.capture.eapol_packets}</div>
          <div class="text-xs text-text-secondary">EAPOL Frames</div>
        </div>
        <div>
          <div class="text-xl font-bold mono">${data.capture.beacon_packets.toLocaleString()}</div>
          <div class="text-xs text-text-secondary">Beacons</div>
        </div>
      </div>
    </div>
  `;

  // Networks
  html += `
    <div class="bg-bg-secondary border border-border-default rounded-lg p-5">
      <h3 class="text-sm font-semibold mb-3 text-text-secondary uppercase tracking-wider">Detected Networks</h3>
      <div class="space-y-2">
        ${data.networks.map(n => `
          <div class="flex items-center justify-between bg-bg-primary rounded px-4 py-2.5">
            <div>
              <span class="font-medium">${n.ssid}</span>
              <span class="text-text-muted mono text-xs ml-2">${n.bssid}</span>
            </div>
            <div class="flex items-center gap-3 text-sm text-text-secondary">
              <span>CH ${n.channel}</span>
              <span class="mono text-xs bg-bg-tertiary px-2 py-0.5 rounded">${n.encryption}</span>
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  // Handshake walkthrough
  data.handshakes.forEach(hs => {
    const statusColor = hs.is_complete ? 'text-accent-green' : 'text-accent-red';
    const statusText = hs.is_complete ? 'Complete (4/4)' : `Incomplete (${hs.stages_found.length}/4)`;

    html += `
      <div class="bg-bg-secondary border border-border-default rounded-lg p-5">
        <div class="flex items-start justify-between mb-4">
          <div>
            <h3 class="text-sm font-semibold text-text-secondary uppercase tracking-wider">4-Way Handshake</h3>
            <p class="text-text-muted text-xs mt-1 mono">${hs.bssid} ↔ ${hs.client_mac} · ${hs.ssid}</p>
          </div>
          <span class="mono text-sm font-semibold ${statusColor}">${statusText}</span>
        </div>

        <!-- Flow diagram -->
        <div class="relative mb-6">
          <div class="flex justify-between text-center text-sm font-medium mb-2 px-8">
            <span class="bg-accent-blue/10 text-accent-blue px-3 py-1 rounded">Access Point</span>
            <span class="bg-accent-purple/10 text-accent-purple px-3 py-1 rounded">Client</span>
          </div>
          ${hs.walkthrough.map((step, i) => {
            const isRight = step.direction.includes('→ Client') || step.direction.includes('→ C');
            const arrowSvg = isRight
              ? `<svg class="w-full h-6" viewBox="0 0 400 24"><line x1="60" y1="12" x2="340" y2="12" stroke="#58a6ff" stroke-width="2"/><polygon points="340,6 354,12 340,18" fill="#58a6ff"/><text x="200" y="10" text-anchor="middle" fill="#8b949e" font-size="10" font-family="JetBrains Mono">MSG ${step.stage}</text></svg>`
              : `<svg class="w-full h-6" viewBox="0 0 400 24"><line x1="60" y1="12" x2="340" y2="12" stroke="#bc8cff" stroke-width="2"/><polygon points="60,6 46,12 60,18" fill="#bc8cff"/><text x="200" y="10" text-anchor="middle" fill="#8b949e" font-size="10" font-family="JetBrains Mono">MSG ${step.stage}</text></svg>`;

            return `
              <div class="mb-3 fade-in" style="animation-delay: ${i * 0.1}s">
                ${arrowSvg}
                <div class="bg-bg-primary rounded-lg p-4 border border-border-default">
                  <div class="flex items-center gap-2 mb-2">
                    <span class="${step.captured ? 'text-accent-green' : 'text-accent-red'}">${step.captured ? '✓' : '✗'}</span>
                    <span class="font-medium text-sm">${step.title}</span>
                  </div>
                  <p class="text-sm text-text-secondary leading-relaxed">${step.summary}</p>
                  <p class="text-xs text-accent-yellow/80 mt-2 italic">${step.security_note}</p>
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;
  });

  // Security recommendations
  html += `
    <div class="bg-bg-secondary border border-border-default rounded-lg p-5">
      <h3 class="text-sm font-semibold mb-3 text-text-secondary uppercase tracking-wider">Security Recommendations</h3>
      <div class="space-y-2">
        ${data.security_summary.recommendations.map(r => `
          <div class="flex items-start gap-2 text-sm">
            <span class="text-accent-green mt-0.5 flex-shrink-0">→</span>
            <span class="text-text-secondary">${r}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  container.innerHTML = html;
}
