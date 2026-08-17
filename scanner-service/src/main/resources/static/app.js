const API_BASE = '/api';
const form = document.getElementById('scan-form');
const stopScanButton = document.getElementById('stop-scan-btn');
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
  if (verdict === 'CANCELLED') return 'pending';
  return 'blocked';
}

function renderStopButton(scan) {
  const shouldShow = scan && ['queued', 'running', 'pending'].includes((scan.status || '').toLowerCase());
  stopScanButton.hidden = !shouldShow;
  stopScanButton.disabled = !shouldShow;
}


function renderStatus(logEntries) {
  statusLog.innerHTML = '';
  const checklist = document.createElement('div');
  checklist.className = 'checklist';

  // Deduplicate checks: keep only the latest status for each check name
  const checkMap = {};
  (logEntries || []).forEach((entry) => {
    const match = /^(.*?):\s*(PENDING|PASS|FAIL|ERROR)\s*(?:-\s*(.*))?$/i.exec(entry);
    if (match) {
      const name = match[1].trim();
      const status = match[2].toUpperCase();
      const details = (match[3] || '').trim();
      checkMap[name] = { status, details };
    }
  });

  // Render deduplicated checks in order they first appeared
  Object.entries(checkMap).forEach(([name, { status, details }]) => {
    const row = document.createElement('div');
    row.className = 'check-row';

    const nameEl = document.createElement('div');
    nameEl.className = 'check-name';
    nameEl.textContent = name;

    const statusEl = document.createElement('span');
    const normalizedStatus = status === 'FAIL' ? 'fail' : status.toLowerCase();
    statusEl.className = `status-pill ${normalizedStatus}`;
    statusEl.textContent = status;

    const detailEl = document.createElement('div');
    detailEl.className = 'check-detail';
    detailEl.textContent = details || 'Check updated';

    row.appendChild(nameEl);
    row.appendChild(statusEl);
    row.appendChild(detailEl);
    checklist.appendChild(row);
  });

  statusLog.appendChild(checklist);
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
  renderStopButton(selected);
  populateDetail(selected);
}

async function pollScan(scanId) {
  if (poller) clearInterval(poller);

  poller = setInterval(async () => {
    const response = await fetch(`${API_BASE}/scans/${scanId}`);
    if (!response.ok) {
      // If the scan is gone (e.g., server restarted) refresh the list and stop polling
      clearInterval(poller);
      poller = null;
      await loadScans();
      return;
    }
    const scan = await response.json();

    if (['passed', 'blocked', 'cancelled', 'error'].includes(scan.status)) {
      clearInterval(poller);
      poller = null;
    }

    renderStatus(scan.log || []);
    await loadScans();
    selectedScanId = scan.id;
    renderStopButton(scan);
    populateDetail(scan);
  }, 1200);
}

stopScanButton.addEventListener('click', async () => {
  if (!selectedScanId) return;

  const response = await fetch(`${API_BASE}/scans/${selectedScanId}/cancel`, { method: 'POST' });
  const scan = await response.json();
  renderStatus(scan.log || ['Scan cancelled.']);
  selectedScanId = scan.id;
  renderStopButton(scan);
  await loadScans();
  populateDetail(scan);
});

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
  renderStopButton(scan);
  await loadScans();
  pollScan(scan.id);
});

loadScans();
