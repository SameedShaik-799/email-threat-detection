/* =============================================
   ThreatScan AI — Frontend JavaScript Logic
   ============================================= */

// ===== Preset Data =====
const PRESETS = {
  safe: {
    subject: 'Meeting Notes – Q4 Planning',
    body: 'Hi team, please find the meeting notes from today attached. Let me know if you have any questions. See the document at https://drive.google.com/file/abc123',
    sender_domain: 'company.com',
    has_attachment: 1, attachment_ext: '.pdf', attachment_size_kb: 420,
  },
  spam: {
    subject: 'BUY NOW! Exclusive 70% OFF – Limited Time Only',
    body: 'Click here to buy our amazing new product at 70% discount! http://bit.ly/cheap-deals Limited offer. Visit http://promo-xyz.biz/offer now! Act fast before stock runs out.',
    sender_domain: 'deals.promo-xyz.biz',
    has_attachment: 0, attachment_ext: '', attachment_size_kb: 0,
  },
  phishing: {
    subject: 'URGENT: Your Account Will Be Suspended in 24 Hours',
    body: 'Dear User, we have detected suspicious activity on your bank account. Please verify your identity immediately by clicking http://paypal-secure-verify.biz/login or your account will be suspended.',
    sender_domain: 'secure-bank-verify.info',
    has_attachment: 0, attachment_ext: '', attachment_size_kb: 0,
  },
  malware: {
    subject: 'Invoice #99482 – Payment Receipt Attached',
    body: 'Please find the attached invoice for your recent transaction. Open the file to review the payment details.',
    sender_domain: 'unknown-billing.com',
    has_attachment: 1, attachment_ext: '.exe', attachment_size_kb: 1024,
  },
};

// ===== Class Colours =====
const CLASS_STYLES = {
  Safe:     { bg: 'linear-gradient(135deg,#16a34a,#22c55e)', text: '#22c55e', icon: '🛡️', rec: 'This email appears to be safe. No threats were detected across content, metadata, URLs, or attachments. No action required.' },
  Spam:     { bg: 'linear-gradient(135deg,#b45309,#f59e0b)', text: '#f59e0b', icon: '📣', rec: 'This email has been classified as Spam. It likely contains unsolicited promotional content. Consider unsubscribing or marking as junk.' },
  Phishing: { bg: 'linear-gradient(135deg,#b91c1c,#ef4444)', text: '#ef4444', icon: '🎣', rec: '⚠️ HIGH RISK — Phishing detected. Do NOT click any links or provide credentials. Report this email to your IT / security team immediately.' },
  Malware:  { bg: 'linear-gradient(135deg,#6d28d9,#8b5cf6)', text: '#8b5cf6', icon: '🦠', rec: '🚨 CRITICAL — Malware threat detected. Do NOT open any attachments. Quarantine this email and alert your security team. Run a system scan.' },
};

const CONF_COLOURS = {
  Safe:     '#22c55e',
  Spam:     '#f59e0b',
  Phishing: '#ef4444',
  Malware:  '#8b5cf6',
};

// ===== DOM References =====
const form                = document.getElementById('email-form');
const submitBtn           = document.getElementById('submit-btn');
const btnText             = submitBtn.querySelector('.btn-text');
const btnLoading          = submitBtn.querySelector('.btn-loading');
const emptyState          = document.getElementById('empty-state');
const resultsEl           = document.getElementById('results');
const verdictBanner       = document.getElementById('verdict-banner');
const verdictIconWrap     = document.getElementById('verdict-icon-wrap');
const verdictIcon         = document.getElementById('verdict-icon');
const verdictLevelEl      = document.getElementById('verdict-level');
const verdictSubjectEl    = document.getElementById('verdict-subject');
const verdictConfidenceEl = document.getElementById('verdict-confidence');
const confidenceBarsEl    = document.getElementById('confidence-bars');
const indicatorsGridEl    = document.getElementById('indicators-grid');
const recommendationEl    = document.getElementById('recommendation');

// ===== Attachment toggle =====
const attNo  = document.getElementById('att-no');
const attYes = document.getElementById('att-yes');
let hasAttachment = 0;
attNo.addEventListener('click',  () => { hasAttachment = 0; attNo.classList.add('active');  attYes.classList.remove('active'); });
attYes.addEventListener('click', () => { hasAttachment = 1; attYes.classList.add('active'); attNo.classList.remove('active'); });

// ===== Preset buttons =====
document.querySelectorAll('.preset-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const key = btn.dataset.preset;
    const p = PRESETS[key];
    document.getElementById('subject').value              = p.subject;
    document.getElementById('body').value                 = p.body;
    document.getElementById('sender_domain').value        = p.sender_domain;
    document.getElementById('attachment_ext').value       = p.attachment_ext;
    document.getElementById('attachment_size_kb').value   = p.attachment_size_kb;

    hasAttachment = p.has_attachment;
    if (hasAttachment) {
      attYes.classList.add('active'); attNo.classList.remove('active');
    } else {
      attNo.classList.add('active'); attYes.classList.remove('active');
    }
  });
});

// ===== Form submit =====
form.addEventListener('submit', async (e) => {
  e.preventDefault();

  const payload = {
    subject:              document.getElementById('subject').value.trim(),
    body:                 document.getElementById('body').value.trim(),
    sender_domain:        document.getElementById('sender_domain').value.trim(),
    has_attachment:       hasAttachment,
    attachment_ext:       document.getElementById('attachment_ext').value,
    attachment_size_kb:   parseFloat(document.getElementById('attachment_size_kb').value) || 0,
  };

  // Show loading
  submitBtn.disabled = true;
  btnText.classList.add('hidden');
  btnLoading.classList.remove('hidden');

  try {
    const resp = await fetch('/api/detect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();

    if (data.error) {
      alert('Error: ' + data.error);
      return;
    }
    renderResults(data);
  } catch (err) {
    alert('Network error: ' + err.message);
  } finally {
    submitBtn.disabled = false;
    btnText.classList.remove('hidden');
    btnLoading.classList.add('hidden');
  }
});

// ===== Render Results =====
function renderResults(data) {
  const threatKey = data.predicted_threat_level;
  const style     = CLASS_STYLES[threatKey];
  const topConf   = data.confidence_scores[threatKey];

  // Show results
  emptyState.classList.add('hidden');
  resultsEl.classList.remove('hidden');
  resultsEl.classList.add('fade-in');

  // Verdict banner
  verdictBanner.style.setProperty('--banner-bg', style.bg);
  verdictBanner.style.borderColor = style.text + '44';
  verdictIconWrap.style.background = style.bg;
  verdictIcon.textContent = style.icon;
  verdictLevelEl.textContent = threatKey;
  verdictLevelEl.style.color = style.text;
  verdictSubjectEl.textContent = '"' + (data.email_subject || '(no subject)') + '"';
  verdictConfidenceEl.textContent = topConf.toFixed(1) + '%';
  verdictConfidenceEl.style.color = style.text;

  // Confidence bars
  confidenceBarsEl.innerHTML = '';
  const order = ['Safe', 'Spam', 'Phishing', 'Malware'];
  order.forEach(cls => {
    const val = data.confidence_scores[cls];
    const row = document.createElement('div');
    row.className = 'conf-row';
    row.innerHTML = `
      <div class="conf-name" style="color:${CONF_COLOURS[cls]}">${cls}</div>
      <div class="conf-track">
        <div class="conf-fill" style="background:${CONF_COLOURS[cls]};width:0%" data-target="${val}"></div>
      </div>
      <div class="conf-pct" style="color:${CONF_COLOURS[cls]}">${val.toFixed(2)}%</div>
    `;
    confidenceBarsEl.appendChild(row);
  });
  // Animate bars after a tiny delay
  setTimeout(() => {
    document.querySelectorAll('.conf-fill').forEach(fill => {
      fill.style.width = fill.dataset.target + '%';
    });
  }, 80);

  // Indicators
  indicatorsGridEl.innerHTML = '';
  const indicators = data.key_indicators;
  Object.entries(indicators).forEach(([key, val]) => {
    const isNum  = typeof val === 'number';
    const isTrue = val === true || (isNum && val > 0);
    const chip = document.createElement('div');
    chip.className = 'indicator-chip ' + (isNum ? 'ind-num' : (isTrue ? 'ind-true' : 'ind-false'));
    const dotColour = isNum ? '#f59e0b' : (isTrue ? '#ef4444' : '#22c55e');
    chip.innerHTML = `
      <span class="ind-dot" style="background:${dotColour};box-shadow:0 0 8px ${dotColour}66"></span>
      <span class="ind-label">${key}</span>
      <span class="ind-val" style="color:${dotColour}">${isNum ? val : (isTrue ? 'YES' : 'NO')}</span>
    `;
    indicatorsGridEl.appendChild(chip);
  });

  // Recommendation
  const recColour = style.text;
  recommendationEl.style.borderColor = recColour + '33';
  recommendationEl.style.background  = hexToRgba(recColour, 0.06);
  recommendationEl.innerHTML = `<strong style="color:${recColour}">Recommendation</strong>${style.rec}`;

  // Scroll to results on mobile
  if (window.innerWidth < 900) {
    document.getElementById('result-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

// ===== Helpers =====
function hexToRgba(hex, alpha) {
  const r = parseInt(hex.slice(1,3),16);
  const g = parseInt(hex.slice(3,5),16);
  const b = parseInt(hex.slice(5,7),16);
  return `rgba(${r},${g},${b},${alpha})`;
}

// Animate dataset bars on scroll
const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.style.width = entry.target.dataset.w;
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.3 });

document.querySelectorAll('.ds-fill').forEach(el => {
  const orig = el.style.width;
  el.dataset.w = orig;
  el.style.width = '0';
  observer.observe(el);
});

// ===== FILE UPLOAD LOGIC =====
const uploadZone    = document.getElementById('upload-zone');
const fileInput     = document.getElementById('email-file-input');
const uploadBrowse  = document.getElementById('upload-browse');
const uploadIdle    = document.getElementById('upload-idle');
const uploadLoading = document.getElementById('upload-loading');
const uploadSuccess = document.getElementById('upload-success');
const uploadFname   = document.getElementById('upload-filename');
const uploadClear   = document.getElementById('upload-clear');

// Open file picker on browse click or zone click
uploadBrowse.addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });
uploadZone.addEventListener('click', () => fileInput.click());

// Drag and drop
uploadZone.addEventListener('dragover', (e) => { e.preventDefault(); uploadZone.classList.add('drag-over'); });
uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('drag-over'));
uploadZone.addEventListener('drop', (e) => {
  e.preventDefault();
  uploadZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) handleFileUpload(file);
});

// File input change
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) handleFileUpload(fileInput.files[0]);
});

// Clear button
uploadClear.addEventListener('click', (e) => {
  e.stopPropagation();
  fileInput.value = '';
  uploadIdle.classList.remove('hidden');
  uploadSuccess.classList.add('hidden');
  uploadLoading.classList.add('hidden');
});

async function handleFileUpload(file) {
  const allowed = ['.eml', '.pdf', '.mhtml', '.mht'];
  const ext = '.' + file.name.split('.').pop().toLowerCase();
  if (!allowed.includes(ext)) {
    alert('Unsupported file. Please upload a .eml or .pdf file.');
    return;
  }

  // Show loading state
  uploadIdle.classList.add('hidden');
  uploadSuccess.classList.add('hidden');
  uploadLoading.classList.remove('hidden');

  try {
    const formData = new FormData();
    formData.append('file', file);

    const resp = await fetch('/api/upload-email', { method: 'POST', body: formData });
    const data = await resp.json();

    if (data.error) {
      alert('Error: ' + data.error);
      uploadIdle.classList.remove('hidden');
      uploadLoading.classList.add('hidden');
      return;
    }

    // Show success state
    uploadLoading.classList.add('hidden');
    uploadSuccess.classList.remove('hidden');
    uploadFname.textContent = file.name + ' — analysed successfully';

    // Auto-fill form fields from parsed data
    if (data.parsed) {
      const p = data.parsed;
      document.getElementById('subject').value            = p.subject || '';
      document.getElementById('body').value               = p.body || '';
      document.getElementById('sender_domain').value      = p.sender_domain || '';
      document.getElementById('attachment_ext').value     = p.attachment_ext || '';
      document.getElementById('attachment_size_kb').value = p.attachment_size_kb || 0;
      hasAttachment = p.has_attachment || 0;
      if (hasAttachment) {
        attYes.classList.add('active'); attNo.classList.remove('active');
      } else {
        attNo.classList.add('active'); attYes.classList.remove('active');
      }
    }

    // Show results immediately
    renderResults(data);
    document.getElementById('result-section').scrollIntoView({ behavior: 'smooth', block: 'start' });

  } catch (err) {
    alert('Upload failed: ' + err.message);
    uploadIdle.classList.remove('hidden');
    uploadLoading.classList.add('hidden');
  }
}

// ===== DATABASE MODAL LOGIC =====
const dbNavBtn      = document.getElementById('db-nav-btn');
const dbModal       = document.getElementById('db-modal');
const dbModalClose  = document.getElementById('db-modal-close');
const dbOverlay     = document.getElementById('db-modal-overlay');
const dbTableBody   = document.getElementById('db-table-body');

const dbStatTotal   = document.getElementById('db-stat-total');
const dbStatSafe    = document.getElementById('db-stat-safe');
const dbStatSpam    = document.getElementById('db-stat-spam');
const dbStatPhish   = document.getElementById('db-stat-phish');
const dbStatMalware = document.getElementById('db-stat-malware');

if (dbNavBtn) {
  dbNavBtn.addEventListener('click', openDatabaseModal);
}
if (dbModalClose) {
  dbModalClose.addEventListener('click', closeDatabaseModal);
}
if (dbOverlay) {
  dbOverlay.addEventListener('click', closeDatabaseModal);
}

function openDatabaseModal() {
  dbModal.classList.remove('hidden');
  fetchDatabaseLogs();
}

function closeDatabaseModal() {
  dbModal.classList.add('hidden');
}

async function fetchDatabaseLogs() {
  try {
    const res = await fetch('/api/history');
    const data = await res.json();
    
    // Update stats counters
    dbStatTotal.textContent = data.total_scanned || 0;
    dbStatSafe.textContent = (data.class_breakdown && data.class_breakdown['Safe']) || 0;
    dbStatSpam.textContent = (data.class_breakdown && data.class_breakdown['Spam']) || 0;
    dbStatPhish.textContent = (data.class_breakdown && data.class_breakdown['Phishing']) || 0;
    dbStatMalware.textContent = (data.class_breakdown && data.class_breakdown['Malware']) || 0;
    
    // Render table rows
    if (!data.recent_scans || data.recent_scans.length === 0) {
      dbTableBody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--text-dim);">No emails logged yet in threats.db. Scan an email to view it here!</td></tr>';
      return;
    }
    
    let html = '';
    data.recent_scans.forEach(row => {
      const cls = (row.predicted_threat || 'safe').toLowerCase();
      const badgeCls = `badge-${cls}`;
      const shortSubj = (row.subject || '(no subject)').length > 35 ? (row.subject.substring(0, 32) + '...') : row.subject;
      const cleanTime = (row.timestamp || '').replace('T', ' ').substring(0, 19);
      
      html += `
        <tr>
          <td>#${row.id}</td>
          <td style="color:var(--text-dim);font-size:0.75rem;">${cleanTime}</td>
          <td title="${row.subject || ''}"><strong>${escapeHtml(shortSubj)}</strong></td>
          <td style="color:var(--text-muted);">${escapeHtml(row.sender_domain || '—')}</td>
          <td><span class="badge-threat ${badgeCls}">${row.predicted_threat}</span></td>
          <td style="font-weight:700;">${row.confidence}%</td>
          <td>${row.url_count}</td>
          <td style="color:var(--text-dim);font-size:0.75rem;">${escapeHtml(row.file_name || 'Manual')}</td>
        </tr>
      `;
    });
    dbTableBody.innerHTML = html;
  } catch (err) {
    dbTableBody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:20px;color:var(--red);">Error reading from SQLite: ${err.message}</td></tr>`;
  }
}

function escapeHtml(text) {
  if (!text) return '';
  return text.replace(/[&<>"']/g, function(m) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
  });
}
