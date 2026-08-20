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
  const box = $('last-run-checks');
  if (!scan) {
    $('last-run-id').textContent = ''; $('last-run-badge').textContent = '—';
    donut({ pass: 0, fail: 0, skip: 0 });
    if (box) box.innerHTML = '<p class="empty">No run selected.</p>';
    return;
  }
  $('last-run-id').textContent = `#${scan.id}`;
  const b = verdictBadge(scan.verdict);
  const badge = $('last-run-badge');
  badge.className = `badge ${b.cls}`;
  badge.textContent = b.label;

  const checkMap = parseChecks(scan.log);
  const checks = Object.values(checkMap);
  donut({
    pass: checks.filter((c) => c.status === 'PASS').length,
    fail: checks.filter((c) => c.status === 'FAIL' || c.status === 'ERROR').length,
    skip: checks.filter((c) => c.status === 'PENDING').length,
  });

  // Named Gate-2 pipeline stages (Unit tests / Integration tests / Security diff review / Semgrep proof / Final verdict)
  if (box) {
    const entries = Object.entries(checkMap);
    box.innerHTML = entries.length ? entries.map(([name, c]) => {
      const pill = c.status === 'PASS' ? 'pass' : (['FAIL', 'ERROR'].includes(c.status) ? 'fail' : 'pending');
      return `<div class="check-row">
        <div class="check-name">${name}</div>
        <span class="status-pill ${pill}">${c.status}</span>
        <div class="check-detail">${c.details || ''}</div>
      </div>`;
    }).join('') : '<p class="empty">Checks appear here once the scan starts.</p>';
  }
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

/* ---------- run form (gate selector) ---------- */
function selectedGate() { return $('gate-select').value; }
function applyGateSelection() {
  const g2 = selectedGate() === 'gate2';
  document.querySelectorAll('.g2-field').forEach((el) => { el.hidden = !g2; });
  document.querySelectorAll('.g1-field').forEach((el) => { el.hidden = g2; });
  $('run-btn').textContent = g2 ? '▶ Run Gate 2' : '▶ Run Gate 1';
  $('gate-desc').textContent = g2
    ? 'Gate 2 — AI security review: injection check → AI review → Semgrep proof → verdict'
    : 'Gate 1 — CI checks: tests, Semgrep, Gitleaks, osv-scanner, Trivy, SBOM (via GitHub Actions or local tools)';
  if (!g2) $('stop-scan-btn').hidden = true;
}
$('gate-select').addEventListener('change', applyGateSelection);
applyGateSelection();

function repoInput() { return $('repo-input').value.trim(); }
function branchInput() { return $('branch-input').value.trim(); }
// Gate 2 clones a URL; accept "owner/name" too by expanding it to a GitHub URL.
function toCloneUrl(v) {
  if (!v) return '';
  if (v.includes('://') || v.startsWith('git@')) return v;
  return 'https://github.com/' + v.replace(/\.git$/, '') + '.git';
}

$('run-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (selectedGate() === 'gate2') {
    const payload = {
      repoUrl: toCloneUrl(repoInput()),
      branch: branchInput() || 'main',
      baseBranch: $('baseBranch').value || 'main',
    };
    const res = await fetch(`${API_BASE}/scans`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    });
    if (!res.ok) return;
    const scan = await res.json();
    selectedScanId = scan.id;
    await loadScans();
    pollScan(scan.id);
  } else {
    // Gate 1 accepts a URL or owner/name directly (backend normalizes it).
    const payload = { mode: $('gate1-mode').value, repo: repoInput() || undefined, ref: branchInput() || undefined };
    const res = await fetch(`${API_BASE}/gate1`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    });
    const run = await res.json();
    renderGate1(run);
    pollGate1(run.id);
    $('gate1-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
});
$('stop-scan-btn').addEventListener('click', async () => {
  if (!selectedScanId) return;
  await fetch(`${API_BASE}/scans/${selectedScanId}/cancel`, { method: 'POST' });
  await loadScans();
});
/* ---------- downloadable PDF report ---------- */
function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// What tool backs each step and what it checks — shown in the report so the reader knows exactly
// which tool ran which test. Matched by substring against the check-row name.
const STEP_META = [
  ['Unit tests', 'Runtime / JUnit', 'Verifies the review environment and toolchain are ready'],
  ['Integration tests', 'Git', 'Clones the repository and loads the PR diff (base → branch)'],
  ['ripgrep', 'ripgrep', 'Fast regex sweep for security hotspots: hardcoded secrets, command exec, unsafe deserialization, disabled TLS, weak crypto'],
  ['tree-sitter', 'tree-sitter CLI', 'Parses the changed source files into ASTs for a structural summary'],
  ['Red Team', 'RedTeamService (HTTP + nuclei)', 'Live DAST probe of PUBLIC targets in .secgate/services.yaml: security headers, TLS, exposed sensitive paths, admin surface'],
  ['L1', 'LLM — integrity guard', 'Detects prompt-injection / instruction tampering in the diff (untrusted-content check)'],
  ['L2', 'LLM — AI review', 'Broken access control, IDOR, missing authz (OWASP A01)'],
  ['L3', 'LLM — AI review', 'Secrets, PII, sensitive logging, crypto failures (OWASP A02)'],
  ['L4', 'LLM — AI review', 'SQL/command injection, XSS, path traversal, deserialization (OWASP A03)'],
  ['L5', 'LLM — AI review', 'Vulnerable/outdated components & supply-chain risk (OWASP A06)'],
  ['L6', 'LLM — AI review', 'Insecure design & business-logic flaws, fail-open handling (OWASP A04)'],
  ['Semgrep proof', 'Semgrep + Docker sandbox', 'Verifies each AI finding with a generated Semgrep rule, then an optional network-disabled sandbox test — only proven findings block'],
  ['Final verdict', 'OPA policy / decision engine', 'Applies the block-vs-allow policy over the confirmed findings'],
  // Gate-1 tools (when a Gate-1 run is reported)
  ['Semgrep (SAST)', 'Semgrep', 'Static analysis with the p/security-audit ruleset'],
  ['Gitleaks', 'Gitleaks', 'Scans the repo for committed secrets/credentials'],
  ['osv-scanner', 'osv-scanner', 'Checks dependencies against the OSV vulnerability database'],
  ['Trivy', 'Trivy', 'Filesystem vuln + IaC/container misconfig + secret scan'],
  ['Syft', 'Syft', 'Generates the CycloneDX software bill of materials (SBOM)'],
  ['actionlint', 'actionlint', 'Lints GitHub Actions workflow files'],
  ['zizmor', 'zizmor', 'Audits CI/CD workflows for security weaknesses'],
];
function stepMeta(name) {
  const hit = STEP_META.find(([k]) => name.includes(k));
  return hit ? { tool: hit[1], checks: hit[2] } : { tool: '—', checks: '—' };
}

function buildReportHtml(scan) {
  const checkMap = parseChecks(scan.log || []);
  const checks = Object.entries(checkMap);
  const isGate2 = checks.some(([n]) => /^L\d|Gate 2/.test(n)) || (scan.findings || []).some((f) => (f.layer || '').includes('Gate 2'));
  const gate = isGate2 ? 'Gate 2 — AI Security Review' : 'Security Gate';
  const findings = scan.findings || [];
  const pass = checks.filter(([, c]) => c.status === 'PASS').length;
  const fail = checks.filter(([, c]) => ['FAIL', 'ERROR'].includes(c.status)).length;
  const skip = checks.filter(([, c]) => !['PASS', 'FAIL', 'ERROR'].includes(c.status)).length;
  const pillCls = (s) => s === 'PASS' ? 'ok' : (['FAIL', 'ERROR'].includes(s) ? 'bad' : 'skip');
  const sevCls = (s) => ['HIGH', 'CRITICAL'].includes((s || '').toUpperCase()) ? 'bad' : ((s || '').toUpperCase() === 'MEDIUM' ? 'warn' : 'skip');
  const title = `security-report-scan-${scan.id}`;

  // Severity breakdown + verdict rationale.
  const sevCount = (s) => findings.filter((f) => (f.severity || '').toUpperCase() === s).length;
  const crit = sevCount('CRITICAL'), high = sevCount('HIGH'), med = sevCount('MEDIUM'), low = sevCount('LOW');
  const confirmed = findings.filter((f) => (f.proofStatus || '').toUpperCase() === 'CONFIRMED').length;
  const blockers = findings.filter((f) => (f.proofStatus || '').toUpperCase() === 'CONFIRMED' && ['HIGH', 'CRITICAL'].includes((f.severity || '').toUpperCase()));
  const rationale = (scan.verdict === 'BLOCKED')
    ? `Blocked because ${blockers.length} confirmed HIGH/CRITICAL finding(s): ${blockers.map((f) => esc(f.title)).join('; ') || 'see findings'}.`
    : (scan.verdict === 'PASS' ? 'Passed — no confirmed HIGH/CRITICAL findings and no integrity failures.' : `Verdict: ${esc(scan.verdict || '—')}.`);

  const stepRows = checks.length ? checks.map(([name, c]) => {
    const m = stepMeta(name);
    return `<tr><td>${esc(name)}</td><td>${esc(m.tool)}</td><td>${esc(m.checks)}</td><td><span class="pill ${pillCls(c.status)}">${esc(c.status)}</span></td><td>${esc(c.details || '')}</td></tr>`;
  }).join('') : `<tr><td colspan="5">No steps were recorded.</td></tr>`;

  const findingCards = findings.length ? findings.map((f, i) => `
    <div class="finding">
      <h3><span class="pill ${sevCls(f.severity)}">${esc(f.severity || '—')}</span> ${i + 1}. ${esc(f.title || 'Finding')}</h3>
      <div class="meta">
        ${f.layer ? `<b>Source:</b> ${esc(f.layer)} &nbsp;·&nbsp; ` : ''}
        <b>Location:</b> ${esc(f.file || '—')}${f.line ? ':' + esc(f.line) : ''} &nbsp;·&nbsp;
        <b>${esc(f.cwe || 'CWE-?')}</b> ${esc(f.owasp || '')} &nbsp;·&nbsp;
        <b>Proof:</b> ${esc(f.proofStatus || '—')}
      </div>
      <p>${esc(f.description || 'No description.')}</p>
      <div class="ev"><b>Evidence</b><pre>${esc((f.proof || 'Proof pending.').trim())}</pre></div>
      <div class="fix"><b>Suggested fix:</b> ${esc(f.fix || 'Review the affected code path.')}</div>
    </div>`).join('') : `<p>No findings were reported for this run.</p>`;

  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>
  <style>
    * { box-sizing: border-box; }
    body { font: 13px/1.5 -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; color: #1a1a2e; margin: 32px; }
    h1 { font-size: 22px; margin: 0 0 4px; }
    h2 { font-size: 15px; margin: 24px 0 8px; border-bottom: 2px solid #e5e7eb; padding-bottom: 4px; }
    h3 { font-size: 13px; margin: 0 0 6px; }
    .sub { color: #6b7280; margin: 0 0 16px; }
    table { border-collapse: collapse; width: 100%; font-size: 12px; }
    th, td { border: 1px solid #e5e7eb; padding: 6px 8px; text-align: left; vertical-align: top; }
    th { background: #f3f4f6; }
    .grid { display: grid; grid-template-columns: 140px 1fr; gap: 2px 12px; font-size: 12.5px; margin-bottom: 8px; }
    .grid b { color: #374151; }
    .pill { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; color: #fff; }
    .pill.ok { background: #16a34a; } .pill.bad { background: #dc2626; } .pill.warn { background: #d97706; } .pill.skip { background: #9ca3af; }
    .tally { margin: 4px 0 10px; color: #374151; }
    .finding { border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px 12px; margin: 10px 0; page-break-inside: avoid; }
    .finding .meta { color: #6b7280; font-size: 11.5px; margin-bottom: 6px; }
    .ev pre { background: #0b1020; color: #d6e2ff; padding: 8px; border-radius: 6px; white-space: pre-wrap; word-break: break-word; font-size: 11px; overflow: hidden; }
    .fix { background: #ecfdf5; border-left: 3px solid #16a34a; padding: 6px 8px; border-radius: 4px; }
    pre.log { background: #0b1020; color: #d6e2ff; padding: 10px; border-radius: 6px; white-space: pre-wrap; word-break: break-word; font-size: 11px; }
    @media print { body { margin: 12mm; } h2 { page-break-after: avoid; } }
  </style></head><body>
    <h1>Security Pipeline Report</h1>
    <p class="sub">${esc(gate)} · Scan #${esc(scan.id)} · Verdict <b>${esc(scan.verdict || '—')}</b></p>
    <div class="grid">
      <b>Repository</b><span>${esc(scan.repoUrl || '—')}</span>
      <b>Branch</b><span>${esc(scan.branch || '—')}</span>
      <b>Started</b><span>${esc(scan.createdAt || '—')}</span>
      <b>Status</b><span>${esc(scan.status || '—')}</span>
      <b>Verdict</b><span>${esc(scan.verdict || '—')}</span>
      <b>Summary</b><span>${esc(scan.summary || '—')}</span>
      <b>Generated</b><span>${esc(new Date().toISOString())}</span>
    </div>

    <h2>Result summary</h2>
    <div class="grid">
      <b>Verdict</b><span><span class="pill ${scan.verdict === 'BLOCKED' ? 'bad' : (scan.verdict === 'PASS' ? 'ok' : 'skip')}">${esc(scan.verdict || '—')}</span></span>
      <b>Why</b><span>${rationale}</span>
      <b>Findings</b><span>${findings.length} total · ${confirmed} confirmed</span>
      <b>By severity</b><span><span class="pill bad">${crit} critical</span> <span class="pill bad">${high} high</span> <span class="pill warn">${med} medium</span> <span class="pill skip">${low} low</span></span>
      <b>Steps</b><span><span class="pill ok">${pass} passed</span> <span class="pill bad">${fail} failed</span> <span class="pill skip">${skip} skipped/not-run</span></span>
    </div>

    <h2>Steps performed (${checks.length}) — which tool ran which test</h2>
    <table><thead><tr><th>Step</th><th>Tool</th><th>What it checks</th><th>Result</th><th>Details</th></tr></thead><tbody>${stepRows}</tbody></table>

    <h2>Findings (${findings.length})</h2>
    ${findingCards}

    <h2>Full execution log</h2>
    <pre class="log">${esc((scan.log || []).join('\n'))}</pre>
  </body></html>`;
}

function downloadReport() {
  const scan = selectedScan();
  if (!scan) { alert('Select a scan run first — click a row under "Recent Scan Runs".'); return; }
  const html = buildReportHtml(scan);
  // Render into a hidden iframe and invoke the browser's print dialog → "Save as PDF".
  const iframe = document.createElement('iframe');
  iframe.style.cssText = 'position:fixed;right:0;bottom:0;width:0;height:0;border:0;';
  document.body.appendChild(iframe);
  const doc = iframe.contentWindow.document;
  doc.open(); doc.write(html); doc.close();
  const go = () => {
    try { iframe.contentWindow.focus(); iframe.contentWindow.print(); }
    catch (e) { alert('Could not open the print dialog: ' + e); }
    setTimeout(() => iframe.remove(), 2000);
  };
  if (iframe.contentWindow.document.readyState === 'complete') setTimeout(go, 50);
  else iframe.onload = () => setTimeout(go, 50);
}

$('view-report').addEventListener('click', downloadReport);

/* nav + theme */
document.querySelectorAll('.nav-item').forEach((item) => item.addEventListener('click', () => {
  document.querySelectorAll('.nav-item').forEach((n) => n.classList.remove('active'));
  item.classList.add('active');
  const map = { dashboard: 'main', new: 'new', runs: 'runs-body', gate1: 'new', failures: 'failures' };
  const target = document.getElementById(map[item.dataset.nav]) || document.querySelector('.main');
  target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  if (item.dataset.nav === 'new') { $('gate-select').value = 'gate2'; applyGateSelection(); $('repo-input').focus(); }
  if (item.dataset.nav === 'gate1') { $('gate-select').value = 'gate1'; applyGateSelection(); }
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
  $('gate1-panel').hidden = false;
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
loadScans();
