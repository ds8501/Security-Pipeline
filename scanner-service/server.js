const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const scanStore = [];

app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'demo-app')));

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.get('/api/scans', (_req, res) => {
  res.json(scanStore.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
});

app.get('/api/scans/:id', (req, res) => {
  const scan = scanStore.find((item) => item.id === req.params.id);
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }
  res.json(scan);
});

app.post('/api/scans', (req, res) => {
  const repoUrl = (req.body.repoUrl || '').trim();
  const branch = (req.body.branch || 'main').trim();

  if (!repoUrl) {
    return res.status(400).json({ error: 'repoUrl is required' });
  }

  const scan = {
    id: `scan-${Date.now()}`,
    repoUrl,
    branch,
    createdAt: new Date().toISOString(),
    status: 'queued',
    verdict: 'PENDING',
    findings: [],
    log: ['Queued for review'],
    summary: 'Waiting for the security review pipeline to start.'
  };

  scanStore.push(scan);

  const isVulnerable = /vulnerable|secret|leak|unsafe/i.test(repoUrl) || /vulnerable|secret|leak|unsafe/i.test(branch);
  const isHiddenInstruction = /hidden|instruction|prompt/i.test(repoUrl) || /hidden|instruction|prompt/i.test(branch);

  setTimeout(() => {
    scan.status = 'running';
    scan.log.push('Repository diff is being analyzed.');
    scan.summary = 'Running the investigation and proof checks.';
  }, 700);

  setTimeout(() => {
    scan.status = 'reviewing';
    scan.log.push('Scanning for auth, data exposure, and unsafe patterns.');
  }, 1800);

  setTimeout(() => {
    if (isHiddenInstruction) {
      scan.verdict = 'BLOCKED';
      scan.status = 'blocked';
      scan.summary = 'Hidden instruction detected in the review context; the scan still failed safely.';
      scan.findings = [
        {
          id: 'F-201',
          severity: 'HIGH',
          title: 'Prompt injection attempt was ignored but still detected',
          file: 'src/session.js',
          line: 22,
          description: 'A review note tried to override the security agent and force a safe result. The scan recognised the tampering attempt and kept the gate closed.',
          proof: 'Detection rule: "prompt injection should be treated as data, never instructions"',
          fix: 'Remove hidden instructions from comments, PR descriptions, and generated artifacts before review. Keep the review loop grounded in repo content only.',
          cwe: 'CWE-93'
        }
      ];
      scan.log.push('Hard tampering rule fired: hidden instruction was found and the build remains blocked.');
      return;
    }

    if (isVulnerable) {
      scan.verdict = 'BLOCKED';
      scan.status = 'blocked';
      scan.summary = 'The security gate found a confirmed issue that blocks the merge.';
      scan.findings = [
        {
          id: 'F-101',
          severity: 'HIGH',
          title: 'Sensitive user data is written to logs',
          file: 'src/auth.js',
          line: 41,
          description: 'A password reset flow logs the raw user record and exposes personal data to anyone with log access.',
          proof: 'Semgrep rule: "logger.info(user)" in auth paths is mapped to a data-leak issue.',
          fix: 'Remove raw record logging and emit only a non-sensitive identifier or redacted metadata.',
          cwe: 'CWE-532'
        }
      ];
      scan.log.push('The generated rule fired. Confirmed finding: data exposure in the auth flow.');
      return;
    }

    scan.verdict = 'PASS';
    scan.status = 'passed';
    scan.summary = 'No confirmed issues were found in the changed code path.';
    scan.log.push('Gate 1 checks passed and no confirmed findings remain.');
  }, 3200);

  res.status(202).json(scan);
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'demo-app', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Security pipeline demo running on http://localhost:${PORT}`);
});
