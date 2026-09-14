/**
 * GridGuard — Dashboard Application
 * Manages WebSocket connection, real-time updates, approval modal,
 * incident reports, and attack injection UI.
 */

'use strict';


// ── Config ───────────────────────────────────────────────────────────────────
const WS_RECONNECT_DELAY = 3000;
const PHOENIX_POLL_INTERVAL = 15000;
const REPORT_POLL_INTERVAL = 8000;

// ── State ────────────────────────────────────────────────────────────────────
const state = {
  ws: null,
  wsConnected: false,
  nodes: {},
  timelineEvents: [],
  reports: [],
  pendingApprovals: {},
  approvalCountdownTimer: null,
  currentApprovalId: null,
  currentReport: null,
  lastTelemetry: null,
};

// ── DOM refs ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initNodes();
  connectWebSocket();
  startClock();
  pollPhoenixStats();
  pollReports();
  setInterval(pollPhoenixStats, PHOENIX_POLL_INTERVAL);
  setInterval(pollReports, REPORT_POLL_INTERVAL);
});

// ── Grid Node Initialization ─────────────────────────────────────────────────
function initNodes() {
  const map = $('grid-map');
  map.innerHTML = '';
  for (let i = 1; i <= 12; i++) {
    const id = `SUBSTATION_${String(i).padStart(3, '0')}`;
    const node = document.createElement('div');
    node.className = 'grid-node node-normal';
    node.id = `node-${id}`;
    node.title = id;
    node.innerHTML = `
      <span class="node-icon">⚡</span>
      <span class="node-id">S${String(i).padStart(3, '0')}</span>
    `;
    node.addEventListener('click', () => showNodeDetail(id));
    map.appendChild(node);
    state.nodes[id] = 'NORMAL';
  }
}

function updateNodes(nodeStates) {
  if (!nodeStates) return;
  let hasThreats = false;

  for (const [id, status] of Object.entries(nodeStates)) {
    const el = $(`node-${id}`);
    if (!el) continue;

    state.nodes[id] = status;

    el.className = 'grid-node';
    el.querySelector('.node-icon').textContent = nodeIcon(status);

    switch (status) {
      case 'THREAT':
        el.classList.add('node-threat');
        hasThreats = true;
        break;
      case 'INVESTIGATING':
        el.classList.add('node-investigating');
        break;
      case 'RESOLVED':
        el.classList.add('node-resolved');
        break;
      default:
        el.classList.add('node-normal');
    }
  }

  // Update map badge
  const badge = $('map-badge');
  if (hasThreats) {
    badge.textContent = '⚠ THREAT DETECTED';
    badge.classList.add('badge-alert');
  } else {
    badge.textContent = 'ALL NOMINAL';
    badge.classList.remove('badge-alert');
  }

  // Update header pill
  const threatCount = Object.values(nodeStates).filter(s => s === 'THREAT').length;
  if (threatCount > 0) {
    $('pill-threats-val').textContent = `${threatCount} Active Threat${threatCount > 1 ? 's' : ''}`;
    $('threat-dot').classList.remove('hidden');
  } else {
    $('pill-threats-val').textContent = 'No Active Threats';
    $('threat-dot').classList.add('hidden');
  }
}

function nodeIcon(status) {
  return { THREAT: '🔴', INVESTIGATING: '🟡', RESOLVED: '🔵', NORMAL: '⚡' }[status] || '⚡';
}

function showNodeDetail(id) {
  const status = state.nodes[id] || 'NORMAL';
  const telem = state.lastTelemetry && state.lastTelemetry.node_id === id ? state.lastTelemetry : null;

  // Find recent timeline events for this node
  const nodeEvents = state.timelineEvents
    .filter(e => e.incident_id && state.timelineEvents.find(
      t => t.incident_id === e.incident_id
    ))
    .slice(0, 3);

  const statusLabel = { THREAT: '🔴 THREAT', INVESTIGATING: '🟡 INVESTIGATING', RESOLVED: '🔵 RESOLVED', NORMAL: '✅ NORMAL' }[status] || status;

  const telemHtml = telem
    ? `<div style="margin-top:8px;font-size:11px;color:#94a3b8">
        Voltage: <b>${telem.voltage?.toFixed(1)}V</b> &nbsp;
        Frequency: <b>${telem.frequency?.toFixed(2)}Hz</b> &nbsp;
        Status: <b>${telem.status || '—'}</b>
       </div>`
    : '';

  // Show as a small toast/popup near the grid
  let popup = $('node-detail-popup');
  if (!popup) {
    popup = document.createElement('div');
    popup.id = 'node-detail-popup';
    popup.style.cssText = `
      position:fixed; bottom:24px; left:24px; z-index:999;
      background:#1e293b; border:1px solid #334155; border-radius:8px;
      padding:14px 18px; min-width:240px; max-width:320px;
      box-shadow:0 4px 24px rgba(0,0,0,0.5); color:#e2e8f0; font-size:13px;
      cursor:pointer;
    `;
    popup.onclick = () => popup.remove();
    document.body.appendChild(popup);
  }

  popup.innerHTML = `
    <div style="font-weight:700;margin-bottom:4px">${escHtml(id)}</div>
    <div>${statusLabel}</div>
    ${telemHtml}
    <div style="margin-top:8px;font-size:10px;color:#64748b">Click to dismiss</div>
  `;

  // Auto-dismiss after 6 seconds
  clearTimeout(popup._timer);
  popup._timer = setTimeout(() => popup?.remove(), 6000);
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
function connectWebSocket() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const url = `${proto}://${location.host}/ws/threats`;

  state.ws = new WebSocket(url);

  state.ws.onopen = () => {
    state.wsConnected = true;
    console.log('[GridGuard] WebSocket connected');
  };

  state.ws.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      handleDashboardUpdate(data);
    } catch (err) {
      console.warn('[GridGuard] WS parse error:', err);
    }
  };

  state.ws.onclose = () => {
    state.wsConnected = false;
    setTimeout(connectWebSocket, WS_RECONNECT_DELAY);
  };

  state.ws.onerror = () => {
    state.ws.close();
  };
}

function handleDashboardUpdate(data) {
  // Update node states
  if (data.node_states) {
    updateNodes(data.node_states);
  }

  // Update telemetry from recent threats
  if (data.recent_threats && data.recent_threats.length > 0) {
    const latest = data.recent_threats[data.recent_threats.length - 1];
    updateTelemetry(latest);
  }

  // Update timeline
  if (data.timeline) {
    updateTimeline(data.timeline);
  }

  // Handle pending approvals
  if (data.pending_approvals && data.pending_approvals.length > 0) {
    const approval = data.pending_approvals[0];
    if (approval.incident_id !== state.currentApprovalId) {
      showApprovalModal(approval);
    }
  } else if (state.currentApprovalId) {
    // Approval was resolved externally
    closeApprovalModal();
  }
}

// ── Telemetry Display ─────────────────────────────────────────────────────────
function updateTelemetry(reading) {
  if (!reading) return;
  state.lastTelemetry = reading;

  const isAnomaly = reading.status === 'ANOMALY';

  const voltageEl = $('telem-voltage');
  const freqEl = $('telem-frequency');
  const nodeEl = $('telem-node');
  const statusEl = $('telem-status');

  voltageEl.textContent = reading.voltage ? `${reading.voltage.toFixed(1)} V` : '— V';
  freqEl.textContent = reading.frequency ? `${reading.frequency.toFixed(2)} Hz` : '— Hz';
  nodeEl.textContent = reading.node_id || '—';
  statusEl.textContent = reading.status || 'NORMAL';

  voltageEl.className = 'telem-value ' + (isAnomaly ? 'telem-anomaly' : 'telem-normal');
  statusEl.className = 'telem-value ' + (isAnomaly ? 'telem-anomaly' : 'telem-normal');
}

// ── Timeline ─────────────────────────────────────────────────────────────────
function updateTimeline(events) {
  if (!events || events.length === 0) return;

  // Only add new events we haven't seen yet
  const existingIds = new Set(state.timelineEvents.map(e => e.id));
  const newEvents = events.filter(e => !existingIds.has(e.id));
  if (newEvents.length === 0) return;

  state.timelineEvents = events;

  const feed = $('timeline-feed');

  // Clear empty placeholder
  const empty = feed.querySelector('.timeline-empty');
  if (empty) empty.remove();

  // Prepend new entries (most recent at top)
  newEvents.forEach(ev => {
    const entry = buildTimelineEntry(ev);
    feed.insertBefore(entry, feed.firstChild);
  });

  // Update count badge
  $('timeline-count').textContent = `${events.length} event${events.length !== 1 ? 's' : ''}`;

  // Cap DOM to 80 entries for performance
  while (feed.children.length > 80) {
    feed.removeChild(feed.lastChild);
  }
}

function buildTimelineEntry(ev) {
  const div = document.createElement('div');
  div.className = `timeline-entry entry-sev-${ev.severity || 'INFO'}`;
  div.id = `entry-${ev.id}`;

  const icon = agentIcon(ev.agent, ev.severity);
  const time = formatTime(ev.timestamp);
  const action = formatAction(ev.action);
  const outcomeClass = ev.outcome ? `outcome-${ev.outcome.toLowerCase()}` : '';
  const conf = ev.confidence != null ? `conf: ${(ev.confidence * 100).toFixed(0)}%` : '';

  div.innerHTML = `
    <span class="entry-icon">${icon}</span>
    <div class="entry-body">
      <div class="entry-top">
        <span class="entry-agent">${escHtml(ev.agent || '—')}</span>
        <span class="entry-time">${time}</span>
      </div>
      <div class="entry-action">${escHtml(action)}</div>
      <div class="entry-reason">${escHtml((ev.reasoning || '').substring(0, 160))}</div>
      <span class="entry-confidence">${conf}</span>
      ${ev.outcome ? `<span class="entry-outcome ${outcomeClass}">${escHtml(ev.outcome)}</span>` : ''}
    </div>
  `;
  return div;
}

function agentIcon(agent, severity) {
  if (severity === 'CRITICAL') return '🚨';
  const icons = {
    detection_agent: '🔍',
    investigation_agent: '🔬',
    response_agent: '⚡',
    operator: '👤',
    gridguard_pipeline: '🤖',
    system: '⚙️',
  };
  return icons[agent] || '•';
}

function formatAction(action) {
  if (!action) return '—';
  return action
    .replace(/_/g, ' ')
    .replace(/tool call:/i, '→ ')
    .replace(/tool result:/i, '← ')
    .replace(/\b\w/g, c => c.toUpperCase());
}

// ── Human Approval Modal ──────────────────────────────────────────────────────
function showApprovalModal(approval) {
  state.currentApprovalId = approval.incident_id;

  $('modal-incident-id').textContent = approval.incident_id || '—';
  $('modal-classification').textContent = approval.classification || '—';
  $('modal-summary').textContent = approval.summary || '—';
  $('modal-reasoning').textContent = approval.ai_reasoning || '—';
  $('modal-playbook').textContent = (approval.recommended_playbook || '—').toUpperCase();

  // MITRE techniques
  const mitreEl = $('modal-mitre');
  const techniques = approval.mitre_techniques || [];
  mitreEl.innerHTML = techniques.length
    ? techniques.map(t => `<div>${escHtml(t.technique_id || '')} — ${escHtml(t.name || '')}</div>`).join('')
    : '—';

  // CVEs
  const cvesEl = $('modal-cves');
  const cves = approval.cves || [];
  cvesEl.innerHTML = cves.length
    ? cves.map(c => `<div>${escHtml(c.id || '')} (CVSS: ${c.cvss_score || '?'})</div>`).join('')
    : '—';

  // Show overlay
  $('approval-overlay').classList.remove('hidden');

  // Start countdown — use backend timeout if provided, default 120s
  const timeout = approval.timeout_seconds || 120;
  startApprovalCountdown(timeout);
}

function startApprovalCountdown(seconds) {
  clearInterval(state.approvalCountdownTimer);
  let remaining = seconds;
  $('approval-countdown').textContent = `${remaining}s`;

  state.approvalCountdownTimer = setInterval(() => {
    remaining--;
    $('approval-countdown').textContent = `${remaining}s`;
    if (remaining <= 0) {
      clearInterval(state.approvalCountdownTimer);
      // Auto-escalate on timeout
      submitApproval('escalated');
    }
  }, 1000);
}

async function submitApproval(result) {
  const id = state.currentApprovalId;
  if (!id) return;

  clearInterval(state.approvalCountdownTimer);

  try {
    let url, method;
    if (result === 'escalated') {
      url = `/api/escalate/${encodeURIComponent(id)}`;
      method = 'POST';
    } else {
      const approved = result === 'approved';
      url = `/api/approve/${encodeURIComponent(id)}?approved=${approved}`;
      method = 'POST';
    }
    await fetch(url, { method });
  } catch (e) {
    console.warn('[GridGuard] Approval submit error:', e);
  }

  closeApprovalModal();
}

function closeApprovalModal() {
  $('approval-overlay').classList.add('hidden');
  state.currentApprovalId = null;
  clearInterval(state.approvalCountdownTimer);
}

// ── Attack Injection ──────────────────────────────────────────────────────────
async function injectAttack(type) {
  const feedback = $('inject-feedback');
  feedback.classList.remove('hidden');
  feedback.textContent = `⏳ Injecting ${type.replace(/_/g, ' ')} attack…`;

  try {
    const res = await fetch(`/api/inject-attack/${type}`, { method: 'POST' });
    const data = await res.json();

    if (res.ok) {
      if (data.status === 'already_running') {
        feedback.textContent = `⚠ ${data.attack_type.replace(/_/g, ' ')} pipeline already running — wait for it to finish`;
        feedback.style.borderColor = 'rgba(251,191,36,0.4)';
        feedback.style.color = 'var(--yellow, #fbbf24)';
      } else {
        feedback.textContent = `✓ Attack injected → ${data.target_node} | Agent pipeline starting…`;
        feedback.style.borderColor = 'rgba(34,197,94,0.4)';
        feedback.style.color = 'var(--green)';
      }

      // Reset feedback after 5s
      setTimeout(() => {
        feedback.classList.add('hidden');
        feedback.style.borderColor = '';
        feedback.style.color = '';
      }, 5000);
    } else {
      feedback.textContent = `✗ Injection failed: ${data.detail || 'unknown error'}`;
      feedback.style.color = 'var(--red)';
    }
  } catch (e) {
    feedback.textContent = `✗ Network error: ${e.message}`;
    feedback.style.color = 'var(--red)';
  }
}

// ── Incident Reports ──────────────────────────────────────────────────────────
async function pollReports() {
  try {
    const res = await fetch('/api/reports');
    if (!res.ok) return;
    const data = await res.json();
    renderReports(data.reports || []);
  } catch (e) {
    // Silent — reports are best-effort
  }
}

function renderReports(reports) {
  if (!reports || reports.length === state.reports.length) return;
  state.reports = reports;

  const list = $('reports-list');
  $('report-count').textContent = `${reports.length} report${reports.length !== 1 ? 's' : ''}`;

  // Clear empty state
  list.innerHTML = '';

  if (reports.length === 0) {
    list.innerHTML = `
      <div class="timeline-empty">
        <div class="empty-icon">📭</div>
        <div>No incidents resolved yet</div>
      </div>`;
    return;
  }

  reports.forEach(r => {
    const card = document.createElement('div');
    const sev = r.classification || 'INFO';
    card.className = `report-card sev-${sev}`;
    card.innerHTML = `
      <div class="report-card-top">
        <span class="report-card-id">#${escHtml(r.report_id || r.incident_id)}</span>
        <span class="report-card-time">${formatTime(r.generated_at)}</span>
      </div>
      <div class="report-card-title">${escHtml(r.title || 'Incident Report')}</div>
      <div class="report-card-summary">${escHtml((r.executive_summary || '').substring(0, 120))}…</div>
    `;
    card.addEventListener('click', () => openReportModal(r));
    list.appendChild(card);
  });
}

function openReportModal(report) {
  state.currentReport = report;
  $('replay-btn').classList.toggle('hidden', !report.incident_id);
  $('report-modal-title').textContent = report.title || 'Incident Report';

  const body = $('report-modal-body');
  body.innerHTML = '';

  const sections = [
    { title: 'Executive Summary', text: report.executive_summary },
    { title: 'What Happened', text: report.what_happened },
    { title: 'What the Agent Did', text: report.what_agent_did },
    { title: 'Why Agent Responded', text: report.why_agent_responded },
    { title: 'Outcome', text: report.outcome },
  ];

  sections.forEach(s => {
    if (!s.text) return;
    const sec = document.createElement('div');
    sec.className = 'report-section';
    sec.innerHTML = `
      <div class="report-section-title">${escHtml(s.title)}</div>
      <div class="report-section-body">${escHtml(s.text)}</div>
    `;
    body.appendChild(sec);
  });

  // MITRE Techniques
  if (report.mitre_techniques && report.mitre_techniques.length > 0) {
    const sec = document.createElement('div');
    sec.className = 'report-section';
    sec.innerHTML = `<div class="report-section-title">MITRE ATT&CK ICS Techniques</div>
      <div class="report-tags">
        ${report.mitre_techniques.map(t =>
      `<span class="report-tag tag-mitre" title="${escHtml(t.url || '')}">${escHtml(t.id)} — ${escHtml(t.name)}</span>`
    ).join('')}
      </div>`;
    body.appendChild(sec);
  }

  // CVEs
  if (report.cves && report.cves.length > 0) {
    const sec = document.createElement('div');
    sec.className = 'report-section';
    sec.innerHTML = `<div class="report-section-title">CVEs Identified</div>
      <div class="report-tags">
        ${report.cves.map(c =>
      `<span class="report-tag tag-cve">${escHtml(c.id)} CVSS:${c.cvss_score || '?'} (${escHtml(c.severity || '?')})</span>`
    ).join('')}
      </div>`;
    body.appendChild(sec);
  }

  // Actions Taken
  if (report.actions_taken && report.actions_taken.length > 0) {
    const sec = document.createElement('div');
    sec.className = 'report-section';
    sec.innerHTML = `<div class="report-section-title">Actions Executed</div>
      <div class="report-tags">
        ${report.actions_taken.map(a =>
      `<span class="report-tag tag-action">${escHtml(a.replace(/_/g, ' '))}</span>`
    ).join('')}
      </div>`;
    body.appendChild(sec);
  }

  // Metadata row
  const meta = document.createElement('div');
  meta.className = 'report-section';
  meta.innerHTML = `<div class="report-section-title">Metadata</div>
    <div class="report-section-body">
      <b>Incident ID:</b> ${escHtml(report.incident_id || '—')}<br/>
      <b>Classification:</b> ${escHtml(report.classification || '—')}<br/>
      <b>Playbook:</b> ${escHtml(report.playbook_executed || '—')}<br/>
      <b>Human Approval:</b> ${escHtml(report.human_approval || '—')}<br/>
      <b>Agent Confidence:</b> ${report.agent_confidence != null ? (report.agent_confidence * 100).toFixed(0) + '%' : '—'}<br/>
      <b>False Positive Probability:</b> ${report.false_positive_probability != null ? (report.false_positive_probability * 100).toFixed(0) + '%' : '—'}
    </div>`;
  body.appendChild(meta);

  $('report-overlay').classList.remove('hidden');
}

async function openIncidentReplay() {
  const report = state.currentReport;
  if (!report || !report.incident_id) return;
  const body = $('report-modal-body');
  body.innerHTML = '<div class="timeline-empty">Loading decision replay…</div>';
  try {
    const response = await fetch(`/api/incidents/${encodeURIComponent(report.incident_id)}/replay`);
    if (!response.ok) throw new Error(`Replay unavailable (${response.status})`);
    const replay = await response.json();
    $('report-modal-title').textContent = `Decision Replay — ${replay.incident_id}`;
    body.innerHTML = '';

    const evaluation = replay.evaluation || {};
    const summary = document.createElement('div');
    summary.className = 'report-section';
    summary.innerHTML = `<div class="report-section-title">Replay Summary</div>
      <div class="report-section-body">
        <b>Status:</b> ${escHtml(replay.status || 'unknown')}<br/>
        <b>Attack:</b> ${escHtml(replay.attack_type || 'unknown')}<br/>
        <b>Node:</b> ${escHtml(replay.node_id || 'unknown')}<br/>
        <b>Quality:</b> ${evaluation.quality_score ?? '—'}<br/>
        <b>Hallucination flagged:</b> ${evaluation.hallucination_flagged ? 'Yes' : 'No'}
      </div>`;
    body.appendChild(summary);

    (replay.events || []).forEach(event => {
      const item = document.createElement('div');
      item.className = 'replay-event';
      item.innerHTML = `<div class="replay-event-meta">${formatTime(event.timestamp)} · ${escHtml(event.agent)} · ${escHtml(event.action)}</div>
        <div>${escHtml(event.reasoning || '')}</div>`;
      body.appendChild(item);
    });
  } catch (error) {
    body.innerHTML = `<div class="timeline-empty">${escHtml(error.message)}</div>`;
  }
}

function closeReportModal() {
  $('report-overlay').classList.add('hidden');
  state.currentReport = null;
}

// Close report modal when clicking overlay background
$('report-overlay').addEventListener('click', (e) => {
  if (e.target === $('report-overlay')) closeReportModal();
});

// ── Arize Phoenix Stats ───────────────────────────────────────────────────────
async function pollPhoenixStats() {
  try {
    const res = await fetch('/api/phoenix-stats');
    if (!res.ok) return;
    const data = await res.json();

    $('pstat-traces').textContent = data.total_traces ?? '—';
    $('pstat-hallucinations').textContent = data.hallucination_flags ?? '—';
    $('pstat-quality').textContent = data.avg_quality_score != null
      ? data.avg_quality_score.toFixed(2)
      : '—';
    const observable = data.status === 'connected' || data.status === 'local';
    const phoenixDisabled = data.status === 'disabled';
    $('pstat-status').textContent = data.status === 'connected' ? '✓ Cloud' : (data.status === 'local' ? '✓ Local' : (phoenixDisabled ? '○ Disabled' : '⚠ Offline'));
    $('pstat-status').className = 'pstat-value ' + (observable ? 'pstat-good' : 'pstat-warn');

    $('pill-phoenix-val').textContent = observable
      ? `Observability: ${data.total_traces} traces`
      : (phoenixDisabled ? 'Phoenix: Disabled' : 'Phoenix: Offline');

    if (data.phoenix_url) {
      $('phoenix-link').href = data.phoenix_url;
    }
  } catch (e) {
    $('pill-phoenix-val').textContent = 'Phoenix: Offline';
  }
}

// ── Clock ─────────────────────────────────────────────────────────────────────
function startClock() {
  function tick() {
    const now = new Date();
    $('system-time').textContent = now.toUTCString().split(' ')[4] + ' UTC';
  }
  tick();
  setInterval(tick, 1000);
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function formatTime(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString('en-GB', { hour12: false });
  } catch { return '—'; }
}

function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
