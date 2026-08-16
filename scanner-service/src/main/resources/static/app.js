const API_BASE = '/api';
const form = document.getElementById('scan-form');
const repoUrlInput = document.getElementById('repoUrl');
const branchInput = document.getElementById('branch');
const statusLog = document.getElementById('status-log');
const scanTableBody = document.getElementById('scan-table-body');
const scanDetail = document.getElementById('scan-detail');

let selectedScanId = null;
let poller = null;

function badgeClass(verdict) {
  if (!verdict || verdict === 'PENDING') return 'pending';
  if (verdict === 'PASS') return 'pass';
  return 'blocked';
}

function renderStatus(logEntries) {
  statusLog.innerHTML = '';
  (logEntries || []).forEach((entry) => {
    const item = document.createElement('li');
    item.textContent = entry;
    statusLog.appendChild(item);
  });
}

function renderScanTable(scans) {
  scanTableBody.innerHTML = '';

  if (!scans.length) {
    scanTableBody.innerHTML = '<tr><td colspan="4" class="empty">No scans yet.</td></tr>';
    return;
  }

  scans.forEach((scan) => {
    const row = document.createElement('tr');
    row.addEventListener('click', () => {
      selectedScanId = scan.id;
      populateDetail(scan);
    });

    row.innerHTML = `
      <td>${scan.id}</td>
      <td>${scan.branch || 'main'}</td>
      <td><span class="badge ${badgeClass(scan.verdict)}">${scan.verdict}</span></td>
      <td>${new Date(scan.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</td>
    `;

    scanTableBody.appendChild(row);
  });
}

function populateDetail(scan) {
  if (!scan) {
    scanDetail.innerHTML = '<p class="empty">Select a scan to inspect the findings.</p>';
    return;
  }

  const findings = scan.findings?.length ? scan.findings : [];

  scanDetail.innerHTML = `
    <div class="detail-card">
      <h3>${scan.id}</h3>
      <div class="summary">
        <strong>Repo:</strong> ${scan.repoUrl}<br />
        <strong>Branch:</strong> ${scan.branch || 'main'}<br />
        <strong>Verdict:</strong> <span class="badge ${badgeClass(scan.verdict)}">${scan.verdict}</span>
      </div>
      <p>${scan.summary || 'No summary available yet.'}</p>

      <div class="finding-list">
        ${findings.length ? findings.map((finding) => `
          <article class="finding-item">
            <h4>${finding.title}</h4>
            <div class="meta">${finding.severity} · ${finding.file}:${finding.line} · CWE-${finding.cwe || 'unknown'}</div>
            <p>${finding.description}</p>
            <div class="code-snippet">${finding.proof || 'Proof pending.'}</div>
            <div class="fix-box"><strong>Suggested fix:</strong> ${finding.fix}</div>
          </article>
        `).join('') : '<p class="empty">No findings were confirmed for this run.</p>'}
      </div>
    </div>
  `;
}

async function loadScans() {
  const response = await fetch(`${API_BASE}/scans`);
  const scans = await response.json();
  renderScanTable(scans);

  if (!selectedScanId && scans.length) {
    selectedScanId = scans[0].id;
  }

  const selected = scans.find((scan) => scan.id === selectedScanId) || scans[0];
  populateDetail(selected);
}

async function pollScan(scanId) {
  if (poller) clearInterval(poller);

  poller = setInterval(async () => {
    const response = await fetch(`${API_BASE}/scans/${scanId}`);
    const scan = await response.json();

    if (scan.status === 'passed' || scan.status === 'blocked') {
      clearInterval(poller);
      poller = null;
    }

    renderStatus(scan.log || []);
    await loadScans();
    selectedScanId = scan.id;
    populateDetail(scan);
  }, 1200);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();

  const payload = {
    repoUrl: repoUrlInput.value,
    branch: branchInput.value,
  };

  const response = await fetch(`${API_BASE}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const details = await response.json();
    renderStatus([details.error || 'Failed to start scan.']);
    return;
  }

  const scan = await response.json();
  renderStatus(scan.log || ['Scan requested.']);
  selectedScanId = scan.id;
  await loadScans();
  pollScan(scan.id);
});

loadScans();
