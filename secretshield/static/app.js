const scanForm = document.getElementById('scanForm');
const fileInput = document.getElementById('scanFile');
const message = document.getElementById('scanMessage');
const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';

if (!document.getElementById('incidents')) {
  const section = document.createElement('section'); section.id = 'incidents'; section.className = 'card scans-card';
  section.innerHTML = '<div class="section-head"><div><h2>Incident workflow</h2><p>Track investigation through verified resolution</p></div></div><div class="table-scroll"><table><thead><tr><th>INCIDENT</th><th>SEVERITY</th><th>STATUS</th><th>UPDATED</th><th>ACTION</th></tr></thead><tbody id="incidentRows"><tr><td colspan="5" class="empty">Loading incidents…</td></tr></tbody></table></div><div class="incident-message" role="status"></div>';
  document.querySelector('.main footer')?.before(section);
  const lastNav = document.querySelector('.sidebar .nav:last-of-type');
  if (lastNav) { const link = document.createElement('a'); link.className = 'nav'; link.href = '#incidents'; link.innerHTML = '<span>◷</span>Incidents'; lastNav.after(link); }
}

if (scanForm) {
  fileInput.addEventListener('change', () => {
    document.getElementById('fileLabel').textContent = fileInput.files[0]?.name || 'Choose a file or ZIP archive';
  });
  scanForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!fileInput.files.length) return;
    const button = document.getElementById('scanButton');
    button.disabled = true;
    button.textContent = 'Scanning safely…';
    message.className = 'scan-message';
    message.textContent = 'Gitleaks is inspecting the selected source. This can take a short while.';
    const data = new FormData(scanForm);
    data.set('git_history', document.getElementById('gitHistory').checked ? 'true' : 'false');
    try {
      const response = await fetch('/api/scans', { method: 'POST', headers: { 'X-CSRFToken': csrf, Accept: 'application/json' }, body: data });
      const result = await response.json();
      if (!response.ok) {
        const code = result.scan?.error_code || result.error || 'scan_failed';
        message.className = 'scan-message error';
        message.textContent = `Scan could not complete (${code.replaceAll('_', ' ')}). No secret values were saved.`;
        return;
      }
      message.className = 'scan-message success';
      message.textContent = `Scan complete: ${result.scan.finding_count} potential exposure(s) found. Values are redacted.`;
      if (result.scan.source_type === 'git-history') message.textContent += ' Git history was scanned.';
      await loadFindings();
      await loadIncidents();
      setTimeout(() => location.reload(), 1200);
    } catch (_error) {
      message.className = 'scan-message error';
      message.textContent = 'Could not reach SecretShield. Check the app status and retry.';
    } finally {
      button.disabled = false;
      button.innerHTML = 'Scan for exposed credentials <span>→</span>';
    }
  });
}

const clearHistoryButton = document.getElementById('clearHistory');
if (clearHistoryButton) {
  clearHistoryButton.addEventListener('click', async () => {
    const confirmed = window.confirm(
      'Clear all saved scans, findings, incidents, and incident timelines for this account? This cannot be undone.'
    );
    if (!confirmed) return;

    const message = document.getElementById('clearHistoryMessage');
    clearHistoryButton.disabled = true;
    message.textContent = 'Clearing saved history…';
    try {
      const response = await fetch('/api/demo/reset', {
        method: 'POST',
        headers: { 'X-CSRFToken': csrf, Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not clear saved history.');
      location.reload();
    } catch (error) {
      message.textContent = error.message || 'Could not reach SecretShield. Try again.';
      clearHistoryButton.disabled = false;
    }
  });
}

function addCell(row, value) {
  const cell = document.createElement('td');
  cell.textContent = value;
  row.append(cell);
  return cell;
}

async function loadFindings() {
  const target = document.getElementById('findingRows');
  if (!target) return;
  const heading = document.querySelector('#findings .section-head');
  if (heading && !heading.querySelector('.export-link')) {
    const link = document.createElement('a'); link.className = 'text-link export-link';
    link.href = '/api/reports/findings.csv'; link.textContent = 'Export redacted CSV'; heading.append(link);
  }
  try {
    const response = await fetch('/api/findings', { headers: { Accept: 'application/json' }, cache: 'no-store' });
    if (!response.ok) throw new Error('findings unavailable');
    const { findings } = await response.json();
    const scansResponse = await fetch('/api/scans', { headers: { Accept: 'application/json' }, cache: 'no-store' });
    if (!scansResponse.ok) throw new Error('scans unavailable');
    const { scans } = await scansResponse.json();
    const sourceStatus = new Map((scans || []).map((scan) => [scan.id, scan.status]));
    target.replaceChildren();
    if (!findings.length) {
      const row = document.createElement('tr');
      const cell = addCell(row, 'No findings yet. Upload a source and run a scan.');
      cell.colSpan = 6; cell.className = 'empty'; target.append(row); return;
    }
    for (const finding of findings) {
      const row = document.createElement('tr');
      const severity = addCell(row, finding.severity.toUpperCase());
      severity.className = `severity ${finding.severity}`;
      addCell(row, finding.rule_id);
      addCell(row, finding.file_path);
      addCell(row, String(finding.line_number));
      addCell(row, finding.status);
      const action = document.createElement('td');
      if (finding.status !== 'resolved' && finding.source_scan_status === 'completed') {
        const verification = document.createElement('select'); verification.className = 'scan-select';
        const placeholder = document.createElement('option'); placeholder.value = ''; placeholder.textContent = 'Verify with clean scan…'; verification.append(placeholder);
        for (const scan of scans || []) {
          if (scan.status !== 'completed' || scan.id <= finding.scan_id || scan.source_name !== finding.source_name || scan.source_type !== finding.source_type) continue;
          const option = document.createElement('option'); option.value = String(scan.id); option.textContent = `Scan #${scan.id} · ${scan.source_name}`; verification.append(option);
        }
        const verifyButton = document.createElement('button'); verifyButton.className = 'ack-button'; verifyButton.type = 'button'; verifyButton.textContent = 'Verify';
        verifyButton.addEventListener('click', () => verifyFinding(finding, verification.value));
        action.append(verification, verifyButton);
      }
      if (finding.status === 'open') {
        const button = document.createElement('button');
        button.className = 'ack-button'; button.type = 'button'; button.textContent = 'Acknowledge';
        button.addEventListener('click', () => acknowledge(finding.id)); action.append(button);
      }
      if (finding.status !== 'resolved' && finding.source_scan_status === 'completed') {
        const create = document.createElement('button'); create.className = 'ack-button'; create.type = 'button'; create.textContent = 'Create incident';
        create.addEventListener('click', () => createIncident(finding)); action.append(create);
      }
      if (!action.childElementCount) action.textContent = `Verified by scan #${finding.verified_scan_id}`;
      if (finding.status !== 'resolved' && finding.source_scan_status !== 'completed') action.textContent = `Original scan ${sourceStatus.get(finding.scan_id) || 'unavailable'}; verification disabled`;
      row.append(action); target.append(row);
    }
  } catch (_error) {
    target.replaceChildren();
    const row = document.createElement('tr'); const cell = addCell(row, 'Could not load findings. Refresh and try again.');
    cell.colSpan = 6; cell.className = 'empty'; target.append(row);
  }
}

async function verifyFinding(finding, scanId) {
  if (!scanId) return;
  const message = document.querySelector('.incident-message');
  try {
    const response = await fetch(`/api/findings/${finding.id}/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf }, body: JSON.stringify({ scan_id: Number(scanId) }) });
    const result = await response.json(); if (!response.ok) throw new Error(result.error || 'Verification failed.');
    if (message) message.textContent = `Finding verified resolved by clean scan #${scanId}.`;
    await loadFindings(); await loadIncidents();
  } catch (error) { if (message) message.textContent = error.message; }
}

async function loadIncidents() {
  const target = document.getElementById('incidentRows');
  if (!target) return;
  try {
    const response = await fetch('/api/incidents', { headers: { Accept: 'application/json' }, cache: 'no-store' });
    if (!response.ok) throw new Error('incidents unavailable');
    const { incidents } = await response.json(); target.replaceChildren();
    if (!incidents.length) { const row = document.createElement('tr'); const cell = addCell(row, 'No incidents yet. Create one from a finding to track response.'); cell.colSpan = 5; cell.className = 'empty'; target.append(row); return; }
    for (const incident of incidents) {
      const row = document.createElement('tr'); addCell(row, incident.title); addCell(row, incident.severity.toUpperCase());
      addCell(row, incident.status.replaceAll('_', ' ')); addCell(row, new Date(incident.updated_at).toLocaleString());
      const action = document.createElement('td');
      const timeline = document.createElement('button'); timeline.className = 'ack-button'; timeline.type = 'button'; timeline.textContent = 'Timeline';
      timeline.addEventListener('click', () => showIncidentTimeline(incident.id)); action.append(timeline);
      const next = { open: 'investigating', investigating: 'remediation_pending', remediation_pending: 'resolved', resolved: 'reopened', reopened: 'investigating' }[incident.status];
      if (next) { const button = document.createElement('button'); button.className = 'ack-button'; button.type = 'button'; button.textContent = next.replaceAll('_', ' '); button.addEventListener('click', () => transitionIncident(incident, next)); action.append(button); }
      row.append(action); target.append(row);
    }
  } catch (_error) { target.replaceChildren(); const row = document.createElement('tr'); const cell = addCell(row, 'Could not load incidents. Refresh and retry.'); cell.colSpan = 5; cell.className = 'empty'; target.append(row); }
}

async function showIncidentTimeline(incidentId) {
  const message = document.querySelector('.incident-message');
  try {
    const response = await fetch(`/api/incidents/${incidentId}/events`, { headers: { Accept: 'application/json' }, cache: 'no-store' });
    const result = await response.json(); if (!response.ok) throw new Error(result.error || 'Could not load the timeline.');
    message.textContent = result.events.map((event) => `${new Date(event.created_at).toLocaleString()}: ${event.event_type.replaceAll('_', ' ')} — ${event.message}`).join(' | ') || 'No timeline events.';
  } catch (error) { message.textContent = error.message; }
}

async function createIncident(finding) {
  const message = document.querySelector('.incident-message');
  try {
    const response = await fetch('/api/incidents', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf }, body: JSON.stringify({ finding_id: finding.id, title: `${finding.rule_id} in ${finding.file_path}` }) });
    const result = await response.json(); if (!response.ok) throw new Error(result.error || 'Could not create incident.');
    message.textContent = 'Incident created and linked to this finding.'; await loadIncidents();
  } catch (error) { message.textContent = error.message; }
}

async function transitionIncident(incident, next) {
  const message = document.querySelector('.incident-message'); const body = { status: next };
  if (next === 'resolved') { const notes = window.prompt('Add resolution notes. Related findings must be verified with a clean scan:'); if (!notes) return; body.resolution_notes = notes; }
  try {
    const response = await fetch(`/api/incidents/${incident.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf }, body: JSON.stringify(body) });
    const result = await response.json(); if (!response.ok) throw new Error(result.error || 'Status update failed.');
    message.textContent = `Incident status changed to ${next.replaceAll('_', ' ')}.`; await loadIncidents();
  } catch (error) { message.textContent = error.message; }
}

async function acknowledge(id) {
  try {
    const response = await fetch(`/api/findings/${id}/acknowledge`, { method: 'POST', headers: { 'X-CSRFToken': csrf, Accept: 'application/json' } });
    if (!response.ok) throw new Error('acknowledgement failed');
    await loadFindings();
  } catch (_error) {
    const target = document.getElementById('findingRows');
    const row = document.createElement('tr'); const cell = addCell(row, 'Could not update the finding. Refresh and try again.');
    cell.colSpan = 6; cell.className = 'empty'; target.prepend(row);
  }
}

loadFindings();
loadIncidents();
