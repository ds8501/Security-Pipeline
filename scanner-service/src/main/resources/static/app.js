const API_BASE = '/api';
const $ = (id) => document.getElementById(id);

let scans = [];
let selectedScanId = null;
let selectedFindingIdx = 0;
let poller = null;

/* ---------- helpers ---------- */
function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function shortRepo(url) {
  if (!url) return 'repo';
  return url.replace(/\.git$/, '').split('/').filter(Boolean).pop() || url;
}
function verdictBadge(v) {
  const val = (v || 'PENDING').toUpperCase();
  if (val === 'PASS') return { cls: 'pass', label: 'PASSED' };
  if (val === 'PENDING' || val === 'CANCELLED') return { cls: 'pending', label: val };
  return { cls: 'blocked', label: val === 'BLOCKED' ? 'FAILED' : val };
}
function isRunning(s) {
  return ['queued', 'running', 'pending'].includes((s.status || '').toLowerCase());
}
function parseChecks(log) {
  const map = {};
  (log || []).forEach((entry) => {
    const m = /^(.*?):\s*(PENDING|PASS|FAIL|ERROR)\s*(?:-\s*(.*))?$/i.exec(entry);
    if (m) map[m[1].trim()] = { status: m[2].toUpperCase(), details: (m[3] || '').trim() };
  });
  return map;
}
function sparkline(series, color) {
  if (!series || series.length < 2) series = [0, 0];
  const w = 220, h = 34, pad = 3;
  const max = Math.max(...series, 1), min = Math.min(...series, 0);
  const span = (max - min) || 1;
  const pts = series.map((v, i) => {
    const x = pad + i * (w - 2 * pad) / (series.length - 1);
    const y = h - pad - ((v - min) / span) * (h - 2 * pad);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
    <polyline fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" points="${pts}"/></svg>`;
}

/* ---------- stat cards ---------- */
function renderStats() {
  const total = scans.length;
  const passed = scans.filter((s) => (s.verdict || '') === 'PASS').length;
  const failed = scans.filter((s) => ['BLOCKED', 'ERROR'].includes(s.verdict || '')).length;
  const running = scans.filter(isRunning).length;

  const chrono = scans.slice().reverse().slice(-12);
  const cards = [
    { n: total, label: 'Total Runs', ic: '▦', cls: 'purple', color: '#8b5cf6',
      series: chrono.map((_, i) => i + 1), sub: `${scans.length} scans stored` },
    { n: passed, label: 'Passed', ic: '✓', cls: 'green', color: '#16a34a',
      series: chrono.map((s) => (s.verdict === 'PASS' ? 1 : 0)),
      sub: total ? `${Math.round(passed / total * 100)}% success rate` : '—' },
    { n: failed, label: 'Failed', ic: '✕', cls: 'red', color: '#dc2626',
      series: chrono.map((s) => (['BLOCKED', 'ERROR'].includes(s.verdict) ? 1 : 0)),
      sub: total ? `${Math.round(failed / total * 100)}% failure rate` : '—' },
    { n: running, label: 'Running', ic: '◔', cls: 'amber', color: '#d97706',
      series: chrono.map((s) => (isRunning(s) ? 1 : 0)), sub: 'in progress' },
  ];

  $('stat-cards').innerHTML = cards.map((c) => `
    <div class="stat">
      <div class="stat-top">
        <div class="stat-ic ${c.cls}">${c.ic}</div>
        <div>
          <div class="stat-num">${c.n}</div>
          <div class="stat-label">${c.label}</div>
        </div>
      </div>
      <div class="stat-sub">${c.sub}</div>
      ${sparkline(c.series, c.color)}
    </div>`).join('');
}

/* ---------- recent runs table ---------- */
function renderRuns() {
  $('runs-count').textContent = `${scans.length} total`;
  const body = $('runs-body');
  if (!scans.length) { body.innerHTML = '<tr><td colspan="5" class="empty">No scans yet.</td></tr>'; return; }
  body.innerHTML = scans.slice(0, 8).map((s) => {
    const b = verdictBadge(s.verdict);
    return `<tr data-id="${s.id}" class="${s.id === selectedScanId ? 'selected' : ''}">
      <td>#${s.id}</td>
      <td>${shortRepo(s.repoUrl)}</td>
      <td>${s.branch || 'main'}</td>
      <td><span class="badge ${b.cls}">${b.label}</span></td>
      <td>${fmtTime(s.createdAt)}</td>
    </tr>`;
  }).join('');
  body.querySelectorAll('tr[data-id]').forEach((tr) =>
    tr.addEventListener('click', () => selectScan(Number(tr.dataset.id))));
}

/* ---------- last run donut ---------- */
function donut(counts) {
  const total = counts.pass + counts.fail + counts.skip;
  const wrap = $('donut-wrap');
  const legend = $('donut-legend');
  if (!total) {
    wrap.innerHTML = `<div class="donut" style="background:var(--slate-bg)"><div class="donut-hole"><span class="donut-center">—</span></div></div>`;
    legend.innerHTML = '';
    return;
  }
  const pPass = counts.pass / total * 100, pFail = counts.fail / total * 100;
  const g = `conic-gradient(#16a34a 0 ${pPass}%, #dc2626 ${pPass}% ${pPass + pFail}%, #cbd2e0 ${pPass + pFail}% 100%)`;
  wrap.innerHTML = `<div class="donut" style="background:${g}">
    <div class="donut-hole"><span class="donut-center">${Math.round(pPass)}%</span></div></div>`;
  const rows = [
    { k: 'Passed', v: counts.pass, c: '#16a34a' },
    { k: 'Failed', v: counts.fail, c: '#dc2626' },
    { k: 'Skipped', v: counts.skip, c: '#cbd2e0' },
  ];
  legend.innerHTML = rows.map((r) => `<li>
    <span class="dot" style="background:${r.c}"></span>${r.k}
    <span class="val">${r.v} (${Math.round(r.v / total * 100)}%)</span></li>`).join('');
}
function renderLastRun(scan) {
  if (!scan) { $('last-run-id').textContent = ''; $('last-run-badge').textContent = '—'; donut({ pass: 0, fail: 0, skip: 0 }); return; }
  $('last-run-id').textContent = `#${scan.id}`;
  const b = verdictBadge(scan.verdict);
  const badge = $('last-run-badge');
  badge.className = `badge ${b.cls}`;
  badge.textContent = b.label;
  const checks = Object.values(parseChecks(scan.log));
  const counts = {
    pass: checks.filter((c) => c.status === 'PASS').length,
    fail: checks.filter((c) => c.status === 'FAIL' || c.status === 'ERROR').length,
    skip: checks.filter((c) => c.status === 'PENDING').length,
  };
  donut(counts);
}

/* ---------- failures + detail ---------- */
function renderFailures(scan) {
  const body = $('fails-body');
  const findings = (scan && scan.findings) || [];
  if (!findings.length) {
    body.innerHTML = '<tr><td colspan="3" class="empty">No findings for this run.</td></tr>';
    renderDetail(null);
    return;
  }
  body.innerHTML = findings.map((f, i) => `
    <tr data-idx="${i}" class="${i === selectedFindingIdx ? 'selected' : ''}">
      <td>${f.title || 'Finding'}</td>
      <td><span class="badge ${['HIGH', 'CRITICAL'].includes((f.severity || '').toUpperCase()) ? 'blocked' : 'pending'}">${f.severity || '—'}</span></td>
      <td>${f.file || '—'}${f.line ? ':' + f.line : ''}</td>
    </tr>`).join('');
  body.querySelectorAll('tr[data-idx]').forEach((tr) =>
    tr.addEventListener('click', () => { selectedFindingIdx = Number(tr.dataset.idx); renderFailures(scan); }));
  renderDetail(findings[selectedFindingIdx] || findings[0]);
}
function renderDetail(f) {
  const el = $('detail');
  if (!f) { el.innerHTML = '<p class="empty">Select a finding to see details.</p>'; $('detail-status').textContent = ''; return; }
  $('detail-status').textContent = `${f.proofStatus || ''}`;
  el.innerHTML = `
    <h3>${f.title || 'Finding'}</h3>
    <div class="meta">${f.severity || '—'} · ${f.file || '—'}${f.line ? ':' + f.line : ''} · ${f.cwe || 'CWE-?'} · ${f.owasp || ''}</div>
    <p>${f.description || 'No description.'}</p>
    <div class="code">${(f.proof || 'Proof pending.').replace(/</g, '&lt;')}</div>
    <div class="fix"><strong>Suggested fix:</strong> ${f.fix || 'Review the affected code path.'}</div>`;
}

/* ---------- selection / loading ---------- */
function selectedScan() {
  return scans.find((s) => s.id === selectedScanId) || scans[0] || null;
}
function selectScan(id) {
  selectedScanId = id;
  selectedFindingIdx = 0;
  const s = selectedScan();
  renderRuns();
  renderLastRun(s);
  renderFailures(s);
  $('stop-scan-btn').hidden = !(s && isRunning(s));
}
async function loadScans() {
  const res = await fetch(`${API_BASE}/scans`);
  scans = await res.json();
  if (!selectedScanId && scans.length) selectedScanId = scans[0].id;
  renderStats();
  renderRuns();
  const s = selectedScan();
  renderLastRun(s);
  renderFailures(s);
  $('stop-scan-btn').hidden = !(s && isRunning(s));
}
function pollScan(id) {
  if (poller) clearInterval(poller);
  poller = setInterval(async () => {
    const res = await fetch(`${API_BASE}/scans/${id}`);
    if (!res.ok) { clearInterval(poller); poller = null; await loadScans(); return; }
    const scan = await res.json();
    if (['passed', 'blocked', 'cancelled', 'error'].includes(scan.status)) { clearInterval(poller); poller = null; }
    await loadScans();
  }, 1500);
}

/* ---------- actions ---------- */
$('scan-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const payload = { repoUrl: $('repoUrl').value, branch: $('branch').value, baseBranch: $('baseBranch').value };
  const res = await fetch(`${API_BASE}/scans`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  if (!res.ok) return;
  const scan = await res.json();
  selectedScanId = scan.id;
  await loadScans();
  pollScan(scan.id);
});
$('stop-scan-btn').addEventListener('click', async () => {
  if (!selectedScanId) return;
  await fetch(`${API_BASE}/scans/${selectedScanId}/cancel`, { method: 'POST' });
  await loadScans();
});
$('view-report').addEventListener('click', () => $('failures').scrollIntoView({ behavior: 'smooth' }));

/* nav + theme */
document.querySelectorAll('.nav-item').forEach((item) => item.addEventListener('click', () => {
  document.querySelectorAll('.nav-item').forEach((n) => n.classList.remove('active'));
  item.classList.add('active');
  const map = { dashboard: 'main', new: 'new', runs: 'runs-body', gate1: 'gate1', failures: 'failures' };
  const target = document.getElementById(map[item.dataset.nav]) || document.querySelector('.main');
  target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  if (item.dataset.nav === 'new') $('repoUrl').focus();
}));
$('theme-toggle').addEventListener('click', () => {
  const cur = document.documentElement.getAttribute('data-theme') === 'dark' ? '' : 'dark';
  document.documentElement.setAttribute('data-theme', cur);
  localStorage.setItem('theme', cur);
});
if (localStorage.getItem('theme') === 'dark') document.documentElement.setAttribute('data-theme', 'dark');

/* ---------- Gate 1 (compact) ---------- */
let gate1Poller = null;
function gate1Pill(c) {
  const v = (c.conclusion || c.status || 'queued').toUpperCase();
  if (['SUCCESS', 'PASS'].includes(v)) return { cls: 'pass', label: v };
  if (['FAILURE', 'FAIL', 'BLOCKED', 'ERROR'].includes(v)) return { cls: 'fail', label: v };
  return { cls: 'pending', label: v };
}
function renderGate1(run) {
  const c = run.conclusion || 'PENDING';
  const cls = c === 'PASS' ? 'pass' : (c === 'PENDING' ? 'pending' : 'blocked');
  $('gate1-summary').innerHTML = `<span class="badge ${cls}">${c}</span> <span class="muted">mode=${run.mode || '—'} · ${run.summary || run.status || ''}</span>`;
  const link = $('gate1-run-link');
  if (run.runUrl) { link.href = run.runUrl; link.hidden = false; } else { link.hidden = true; }
  const box = $('gate1-checks');
  box.innerHTML = (run.checks || []).map((chk) => {
    const p = gate1Pill(chk);
    return `<div class="check-row"><div class="check-name">${chk.name}</div>
      <span class="status-pill ${p.cls}">${p.label}</span>
      <div class="check-detail">${(chk.details || chk.status || '').toString().slice(0, 200)}${chk.url ? ` · <a href="${chk.url}" target="_blank" rel="noopener">logs ↗</a>` : ''}</div></div>`;
  }).join('') || '<p class="empty">Waiting for checks…</p>';
}
function pollGate1(id) {
  if (gate1Poller) clearInterval(gate1Poller);
  gate1Poller = setInterval(async () => {
    const res = await fetch(`${API_BASE}/gate1/${id}`);
    if (!res.ok) { clearInterval(gate1Poller); gate1Poller = null; return; }
    const run = await res.json();
    renderGate1(run);
    if (['completed', 'error'].includes(run.status)) { clearInterval(gate1Poller); gate1Poller = null; }
  }, 2000);
}
$('gate1-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const payload = { mode: $('gate1-mode').value, repo: $('gate1-repo').value || undefined, ref: $('gate1-ref').value || undefined };
  const res = await fetch(`${API_BASE}/gate1`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const run = await res.json();
  renderGate1(run);
  pollGate1(run.id);
});

loadScans();
