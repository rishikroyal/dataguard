/**
 * DataGuard AI — Application Controller
 * Handles SPA navigation, local state, event bindings, and UI rendering.
 */

// ── Application State ─────────────────────────────────────────────
const state = {
  documents: [],          // Summaries of all analyzed documents
  currentDocId: null,      // Currently selected document ID
  currentDocDetails: null, // Full details (detections, risk profile) of active doc
  apiKey: localStorage.getItem('dataguard_api_key') || '',
  qaHistory: {},          // { docId: [ { role, text, timestamp } ] }
  activePage: 'home',
  auditLogs: [],
  auditStats: {},
  charts: {}              // Cache ChartJS instances to destroy before redraw
};

// ── UI Theme Risk Config ──────────────────────────────────────────
const RISK_THEMES = {
  CRITICAL: { bg: '#FEE2E2', border: '#FCA5A5', text: '#991B1B', borderClass: 'badge-critical' },
  HIGH:     { bg: '#FEF3C7', border: '#FDE68A', text: '#92400E', borderClass: 'badge-high' },
  MEDIUM:   { bg: '#FEF9C3', border: '#FEF08A', text: '#713F12', borderClass: 'badge-medium' },
  LOW:      { bg: '#DCFCE7', border: '#A7F3D0', text: '#166534', borderClass: 'badge-low' }
};

// ── Initial Setup ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Bind API Key Input
  const keyInput = document.getElementById('api-key-input');
  if (keyInput) {
    keyInput.value = state.apiKey;
    updateAIStatus(state.apiKey);
    keyInput.addEventListener('input', (e) => {
      state.apiKey = e.target.value.trim();
      localStorage.setItem('dataguard_api_key', state.apiKey);
      updateAIStatus(state.apiKey);
    });
  }

  // Handle SPA Hash Routing
  window.addEventListener('hashchange', handleRouting);
  handleRouting();

  // Load Initial Document List
  loadDocuments();

  // Setup File Upload Event Handlers
  setupUploadHandlers();
});

// ── Navigation & Routing ──────────────────────────────────────────
function handleRouting() {
  const hash = window.location.hash.replace('#', '') || 'home';
  navigate(hash);
}

function navigate(pageId) {
  state.activePage = pageId;

  // Toggle page visibility
  document.querySelectorAll('.page').forEach(page => {
    page.classList.toggle('active', page.id === `page-${pageId}`);
  });

  // Toggle active sidebar link
  document.querySelectorAll('.sidebar-nav .nav-link').forEach(link => {
    link.classList.toggle('active', link.dataset.page === pageId);
  });

  // Refresh page contents
  refreshActivePage();
}

function updateAIStatus(key) {
  const statusEl = document.getElementById('ai-status');
  if (statusEl) {
    if (key) {
      statusEl.textContent = 'AI: active';
      statusEl.className = 'ai-status online';
    } else {
      statusEl.textContent = 'AI: offline';
      statusEl.className = 'ai-status offline';
    }
  }
}

function updateSessionStats() {
  const statsEl = document.getElementById('session-stats');
  if (statsEl) {
    const scanCount = state.documents.length;
    statsEl.textContent = `${scanCount} document${scanCount !== 1 ? 's' : ''} analyzed`;
  }
}

// ── Toast Notifications ───────────────────────────────────────────
function showToast(message, isError = false) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = message;
  toast.classList.toggle('error', isError);
  toast.classList.remove('hidden');

  setTimeout(() => {
    toast.classList.add('hidden');
  }, 4000);
}

// ── API Operations & State Sync ───────────────────────────────────
async function loadDocuments() {
  try {
    const res = await window.api.listDocuments();
    state.documents = res.documents;
    updateSessionStats();

    if (state.documents.length > 0 && !state.currentDocId) {
      state.currentDocId = state.documents[0].doc_id;
    }

    if (state.currentDocId) {
      await fetchActiveDocDetails();
    }
    refreshActivePage();
  } catch (err) {
    showToast('Failed to load document list', true);
  }
}

async function fetchActiveDocDetails() {
  if (!state.currentDocId) return;
  try {
    state.currentDocDetails = await window.api.getDocument(state.currentDocId);
  } catch (err) {
    showToast('Failed to load document details', true);
  }
}

async function selectDocument(docId) {
  state.currentDocId = docId;
  await fetchActiveDocDetails();
  
  // Sync all select elements across pages
  document.querySelectorAll('[id$="-doc-select"]').forEach(select => {
    select.value = docId;
  });

  refreshActivePage();
}

// ── Dropzone & Upload Handler ─────────────────────────────────────
function setupUploadHandlers() {
  const dropzone = document.getElementById('upload-dropzone');
  const fileInput = document.getElementById('file-input');

  if (!dropzone || !fileInput) return;

  dropzone.addEventListener('click', () => fileInput.click());

  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });

  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
  });

  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleFileUpload(e.target.files[0]);
    }
  });
}

async function handleFileUpload(file) {
  const progressEl = document.getElementById('upload-progress');
  const fillEl = document.getElementById('progress-fill');
  const labelEl = document.getElementById('progress-label');

  if (!progressEl || !fillEl || !labelEl) return;

  progressEl.classList.remove('hidden');
  fillEl.style.width = '20%';
  labelEl.textContent = 'Extracting document text...';

  try {
    const useOcr = document.getElementById('use-ocr')?.checked || false;
    
    // Simulate progression steps
    setTimeout(() => { fillEl.style.width = '50%'; labelEl.textContent = 'Running pattern detection...'; }, 1000);
    setTimeout(() => { fillEl.style.width = '75%'; labelEl.textContent = 'Classifying risk profiles...'; }, 2200);

    const docResult = await window.api.uploadDocument(file, useOcr, state.apiKey);
    
    fillEl.style.width = '100%';
    labelEl.textContent = 'Complete.';
    showToast(`Successfully analyzed: ${file.name}`);

    setTimeout(() => {
      progressEl.classList.add('hidden');
    }, 1000);

    state.currentDocId = docResult.doc_id;
    await loadDocuments();
  } catch (err) {
    progressEl.classList.add('hidden');
    showToast(err.message || 'File analysis failed', true);
  }
}

async function loadSample(name) {
  const progressEl = document.getElementById('upload-progress');
  const fillEl = document.getElementById('progress-fill');
  const labelEl = document.getElementById('progress-label');

  if (progressEl) progressEl.classList.remove('hidden');
  if (fillEl) fillEl.style.width = '30%';
  if (labelEl) labelEl.textContent = 'Loading sample from server...';

  try {
    const docResult = await window.api.loadSample(name);
    if (fillEl) fillEl.style.width = '100%';
    if (labelEl) labelEl.textContent = 'Done.';
    showToast(`Loaded sample: ${docResult.filename}`);

    setTimeout(() => {
      if (progressEl) progressEl.classList.add('hidden');
    }, 800);

    state.currentDocId = docResult.doc_id;
    await loadDocuments();
  } catch (err) {
    if (progressEl) progressEl.classList.add('hidden');
    showToast('Failed to load sample document', true);
  }
}

function clearDocuments() {
  // Client-side reset since backend store is in-memory and lightweight anyway.
  state.documents = [];
  state.currentDocId = null;
  state.currentDocDetails = null;
  state.qaHistory = {};
  updateSessionStats();
  refreshActivePage();
  showToast('Session cleared');
}

// ── Document Selector Sync ────────────────────────────────────────
function renderDocSelector(containerId, selectId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  if (state.documents.length === 0) {
    container.classList.add('hidden');
    return;
  }

  container.classList.remove('hidden');
  container.innerHTML = `
    <label class="section-label" for="${selectId}">Active Document</label>
    <select id="${selectId}" class="select" style="width:100%;">
      ${state.documents.map(doc => `
        <option value="${doc.doc_id}" ${doc.doc_id === state.currentDocId ? 'selected' : ''}>
          ${doc.filename} (${doc.risk_level})
        </option>
      `).join('')}
    </select>
  `;

  const select = document.getElementById(selectId);
  select.addEventListener('change', (e) => {
    selectDocument(e.target.value);
  });
}

// ── Refresh Screen Router ─────────────────────────────────────────
function refreshActivePage() {
  switch (state.activePage) {
    case 'upload':
      renderUploadPage();
      break;
    case 'detection':
      renderDetectionPage();
      break;
    case 'dashboard':
      renderDashboardPage();
      break;
    case 'qa':
      renderQAPage();
      break;
    case 'reports':
      renderReportsPage();
      break;
    case 'audit':
      renderAuditPage();
      break;
  }
}

// ── 1. Upload Page View ───────────────────────────────────────────
function renderUploadPage() {
  const docListSection = document.getElementById('doc-list-section');
  const docList = document.getElementById('doc-list');
  const docStats = document.getElementById('doc-stats');
  
  if (!docListSection || !docList || !docStats) return;

  if (state.documents.length === 0) {
    docListSection.classList.add('hidden');
    docStats.classList.add('hidden');
    return;
  }

  docListSection.classList.remove('hidden');

  // Render Document Rows
  docList.innerHTML = state.documents.map(doc => {
    const isSelected = doc.doc_id === state.currentDocId;
    const theme = RISK_THEMES[doc.risk_level] || RISK_THEMES.LOW;
    const borderStyle = isSelected ? 'border-color:#111111; background:#F9F9F9;' : '';

    return `
      <div class="card" style="display:flex; justify-content:space-between; align-items:center; cursor:pointer; ${borderStyle}" onclick="selectDocument('${doc.doc_id}')">
        <div>
          <div style="font-weight:600; font-size:0.9rem; color:#111111;">${doc.filename}</div>
          <div style="font-size:0.75rem; color:#888888; margin-top:2px;">
            ${doc.format.toUpperCase()} · ${(doc.file_size / 1024).toFixed(1)} KB · ${doc.word_count.toLocaleString()} words · ${doc.processed_at}
          </div>
        </div>
        <div style="text-align:right;">
          <span class="badge ${theme.borderClass}">${doc.risk_level}</span>
          <div style="font-size:0.72rem; color:#888888; margin-top:4px;">${doc.detection_count} findings</div>
        </div>
      </div>
    `;
  }).join('');

  // Render selected document stats
  if (state.currentDocDetails) {
    docStats.classList.remove('hidden');
    const doc = state.currentDocDetails;
    const rp = doc.risk_profile;
    const theme = RISK_THEMES[doc.risk_level] || RISK_THEMES.LOW;

    // Stat Strip
    document.getElementById('stat-strip').innerHTML = `
      <div class="stat-cell"><div class="stat-val">${doc.detection_count}</div><div class="stat-lbl">Findings</div></div>
      <div class="stat-cell"><div class="stat-val" style="color:#991B1B;">${rp.critical_count}</div><div class="stat-lbl">Critical</div></div>
      <div class="stat-cell"><div class="stat-val" style="color:#92400E;">${rp.high_count}</div><div class="stat-lbl">High</div></div>
      <div class="stat-cell"><div class="stat-val" style="color:#713F12;">${rp.medium_count}</div><div class="stat-lbl">Medium</div></div>
      <div class="stat-cell"><div class="stat-val" style="color:#166534;">${rp.low_count}</div><div class="stat-lbl">Low</div></div>
      <div class="stat-cell"><div class="stat-val">${doc.risk_score.toFixed(0)}</div><div class="stat-lbl">Score /100</div></div>
    `;

    // Risk Banner
    const banner = document.getElementById('risk-banner');
    banner.style.background = theme.bg;
    banner.style.color = theme.text;
    banner.style.border = `1px solid ${theme.border}`;
    banner.innerHTML = `
      <div>
        <div style="font-size:0.65rem; text-transform:uppercase; font-weight:600; letter-spacing:0.5px;">Document Risk Classification</div>
        <div class="risk-level-text">${doc.risk_level}</div>
      </div>
      <div style="flex:1; border-left:1px solid ${theme.border}80; padding-left:1rem;" class="risk-clearance">
        ${rp.document_clearance}
      </div>
    `;
  } else {
    docStats.classList.add('hidden');
  }
}

// ── 2. Detection Page View ────────────────────────────────────────
let detectionFilters = {
  type: 'ALL',
  risk: 'ALL',
  search: ''
};

function renderDetectionPage() {
  renderDocSelector('detection-doc-selector', 'detection-doc-select');

  const content = document.getElementById('detection-content');
  if (!content) return;

  if (!state.currentDocDetails) {
    content.innerHTML = `<div class="empty-state">No documents analyzed yet. <a href="#upload" onclick="navigate('upload')">Upload one →</a></div>`;
    return;
  }

  const doc = state.currentDocDetails;
  const detections = doc.detections || [];

  if (detections.length === 0) {
    content.innerHTML = `
      <div class="empty-state" style="border-style:solid; background:#FFFFFF;">
        <span style="font-size:1.5rem; display:block; margin-bottom:0.5rem;">✓</span>
        <strong>Clean document.</strong> No sensitive data or compliance issues identified.
      </div>
    `;
    return;
  }

  // Get distinct types for filtering
  const distinctTypes = [...new Set(detections.map(d => d.type))];

  // Apply filters
  const filtered = detections.filter(d => {
    const matchesType = detectionFilters.type === 'ALL' || d.type === detectionFilters.type;
    const matchesRisk = detectionFilters.risk === 'ALL' || d.risk === detectionFilters.risk;
    
    const patternName = d.pattern || '';
    const maskedValue = d.masked_value || '';
    const searchStr = detectionFilters.search || '';
    
    const matchesSearch = patternName.toLowerCase().includes(searchStr.toLowerCase()) ||
                          maskedValue.toLowerCase().includes(searchStr.toLowerCase());
    return matchesType && matchesRisk && matchesSearch;
  });

  // Filter UI
  let filterBarHtml = `
    <div class="filter-bar">
      <input type="text" id="det-search" placeholder="Search findings…" value="${detectionFilters.search}" style="flex:1; min-width:180px;" />
      <select id="det-filter-type">
        <option value="ALL">All Types</option>
        ${distinctTypes.map(t => `<option value="${t}" ${detectionFilters.type === t ? 'selected' : ''}>${t}</option>`).join('')}
      </select>
      <select id="det-filter-risk">
        <option value="ALL">All Risk Levels</option>
        <option value="CRITICAL" ${detectionFilters.risk === 'CRITICAL' ? 'selected' : ''}>Critical</option>
        <option value="HIGH" ${detectionFilters.risk === 'HIGH' ? 'selected' : ''}>High</option>
        <option value="MEDIUM" ${detectionFilters.risk === 'MEDIUM' ? 'selected' : ''}>Medium</option>
        <option value="LOW" ${detectionFilters.risk === 'LOW' ? 'selected' : ''}>Low</option>
      </select>
    </div>
  `;

  // Render cards
  const cardsHtml = filtered.map(d => {
    const theme = RISK_THEMES[d.risk] || RISK_THEMES.LOW;
    
    // Mask any raw sensitive value that appears inside this context snippet
    let cleanContext = d.context || '';
    detections.forEach(other => {
      if (other.value) {
        const escapedVal = other.value.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
        const re = new RegExp(escapedVal, 'g');
        cleanContext = cleanContext.replace(re, other.masked_value);
      }
    });

    return `
      <div class="det-item">
        <div class="det-header">
          <div>
            <span class="badge ${theme.borderClass}">${d.risk}</span>
            <span class="det-type" style="margin-left:0.5rem;">${d.type}</span>
          </div>
          <div class="det-meta">
            ${d.line_number ? `Line ${d.line_number} · ` : ''}${(d.confidence * 100).toFixed(0)}% confidence
          </div>
        </div>
        <div class="det-value">${escapeHtml(d.masked_value)}</div>
        <div class="det-context">…${escapeHtml(cleanContext)}…</div>
      </div>
    `;
  }).join('');

  content.innerHTML = `
    ${filterBarHtml}
    <div class="section-label">Findings (${filtered.length} of ${detections.length})</div>
    <div class="det-list">${cardsHtml || '<div class="empty-state">No findings match active filters.</div>'}</div>
  `;

  // Bind filter events
  document.getElementById('det-search').addEventListener('input', (e) => {
    detectionFilters.search = e.target.value;
    renderDetectionPage();
  });
  document.getElementById('det-filter-type').addEventListener('change', (e) => {
    detectionFilters.type = e.target.value;
    renderDetectionPage();
  });
  document.getElementById('det-filter-risk').addEventListener('change', (e) => {
    detectionFilters.risk = e.target.value;
    renderDetectionPage();
  });
}

// ── 3. Dashboard Page View ────────────────────────────────────────
function renderDashboardPage() {
  renderDocSelector('dashboard-doc-selector', 'dashboard-doc-select');

  const content = document.getElementById('dashboard-content');
  if (!content) return;

  if (!state.currentDocDetails) {
    content.innerHTML = `<div class="empty-state">No documents analyzed yet. <a href="#upload" onclick="navigate('upload')">Upload one →</a></div>`;
    return;
  }

  const doc = state.currentDocDetails;
  const rp = doc.risk_profile;

  // Clean ChartJS instances
  Object.keys(state.charts).forEach(key => {
    if (state.charts[key]) {
      state.charts[key].destroy();
      state.charts[key] = null;
    }
  });

  content.innerHTML = `
    <div class="row" style="gap:1rem; margin-bottom:1rem; align-items:stretch;">
      <div class="col" style="flex: 1.2;">
        <div class="score-box" style="height:100%; display:flex; flex-direction:column; justify-content:center;">
          <div class="score-label">Document Risk Score</div>
          <div class="score-num">${doc.risk_score.toFixed(0)}<span class="score-denom">/100</span></div>
          <div class="row justify-center mt-1">
            <span class="badge ${RISK_THEMES[doc.risk_level].borderClass}">${doc.risk_level}</span>
          </div>
          <div style="font-size:0.8rem; color:#666666; margin-top:0.75rem; line-height:1.4;">
            ${rp.document_clearance}
          </div>
        </div>
      </div>
      <div class="col" style="flex: 2;">
        <div class="chart-card" style="height:100%;">
          <div class="chart-title">Risk Breakdown</div>
          <div class="chart-canvas-wrap">
            <canvas id="chart-pie"></canvas>
          </div>
        </div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="chart-card">
        <div class="chart-title">Findings by Category</div>
        <div class="chart-canvas-wrap">
          <canvas id="chart-bar"></canvas>
        </div>
      </div>
      <div class="chart-card">
        <div class="chart-title">Confidence Distribution</div>
        <div class="chart-canvas-wrap">
          <canvas id="chart-confidence"></canvas>
        </div>
      </div>
    </div>

    <!-- Compliance Exposure mapping -->
    <div class="row" style="gap:1rem; margin-top:1rem; align-items:stretch;">
      <div class="col" style="border:1px solid #E8E8E8; border-radius:8px; padding:1.25rem;">
        <div class="section-label">🇮🇳 India DPDP Act 2023 Compliance</div>
        <div class="pill-list">
          ${(rp.dpdp_violations || []).length > 0 
            ? rp.dpdp_violations.map(v => `<span class="pill">${v}</span>`).join('')
            : '<span class="text-muted text-sm">No violations found</span>'}
        </div>
      </div>
      <div class="col" style="border:1px solid #E8E8E8; border-radius:8px; padding:1.25rem;">
        <div class="section-label">🇪🇺 EU GDPR Compliance</div>
        <div class="pill-list">
          ${(rp.gdpr_violations || []).length > 0 
            ? rp.gdpr_violations.map(v => `<span class="pill">${v}</span>`).join('')
            : '<span class="text-muted text-sm">No violations found</span>'}
        </div>
      </div>
    </div>

    <div style="border:1px solid #E8E8E8; border-radius:8px; padding:1.25rem; margin-top:1rem;">
      <div class="section-label">Risk Exposure Summary</div>
      <div style="display:flex; flex-direction:column; gap:0.4rem;">
        ${(rp.risk_factors || []).map(rf => {
          const isWarning = rf.includes('⚠️');
          return `
            <div style="font-size:0.83rem; color:${isWarning ? '#92400E' : '#166534'}; 
                        background:${isWarning ? '#FEF3C7' : '#DCFCE7'}; 
                        padding:0.4rem 0.75rem; border-radius:5px;">
              ${rf}
            </div>
          `;
        }).join('')}
      </div>
    </div>
  `;

  // Draw charts asynchronously to ensure DOM nodes are ready
  setTimeout(() => {
    drawCharts(doc);
  }, 50);
}

function drawCharts(doc) {
  const rp = doc.risk_profile;
  const detections = doc.detections;

  // 1. Pie/Donut Chart
  const pieCtx = document.getElementById('chart-pie');
  if (pieCtx) {
    const labels = Object.keys(rp.risk_breakdown).filter(k => rp.risk_breakdown[k] > 0);
    const data = labels.map(k => rp.risk_breakdown[k]);
    const backgroundColors = labels.map(l => {
      if (l === 'CRITICAL') return '#DC2626';
      if (l === 'HIGH') return '#D97706';
      if (l === 'MEDIUM') return '#CA8A04';
      return '#16A34A';
    });

    state.charts.pie = new Chart(pieCtx, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{
          data,
          backgroundColor: backgroundColors,
          borderWidth: 0,
          hoverOffset: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'right', labels: { boxWidth: 12, font: { family: 'Inter' } } }
        }
      }
    });
  }

  // 2. Bar Chart (Type counts)
  const barCtx = document.getElementById('chart-bar');
  if (barCtx) {
    const typeCounts = {};
    detections.forEach(d => {
      typeCounts[d.type] = (typeCounts[d.type] || 0) + 1;
    });

    const labels = Object.keys(typeCounts).sort((a,b) => typeCounts[b] - typeCounts[a]);
    const data = labels.map(l => typeCounts[l]);

    state.charts.bar = new Chart(barCtx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Findings',
          data,
          backgroundColor: '#111111',
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, grid: { color: '#F3F3F3' } },
          x: { grid: { display: false } }
        }
      }
    });
  }

  // 3. Confidence Distribution (Histogram approximation)
  const confCtx = document.getElementById('chart-confidence');
  if (confCtx) {
    const bins = Array(5).fill(0);
    detections.forEach(d => {
      const idx = Math.min(Math.floor(d.confidence * 5), 4);
      bins[idx]++;
    });

    state.charts.confidence = new Chart(confCtx, {
      type: 'bar',
      data: {
        labels: ['0-20%', '20-40%', '40-60%', '60-80%', '80-100%'],
        datasets: [{
          data: bins,
          backgroundColor: '#888888',
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, grid: { color: '#F3F3F3' } },
          x: { grid: { display: false } }
        }
      }
    });
  }
}

// ── 4. Q&A Page View ──────────────────────────────────────────────
function renderQAPage() {
  renderDocSelector('qa-doc-selector', 'qa-doc-select');

  const content = document.getElementById('qa-content');
  if (!content) return;

  if (!state.currentDocDetails) {
    content.innerHTML = `<div class="empty-state">No documents analyzed yet. <a href="#upload" onclick="navigate('upload')">Upload one →</a></div>`;
    return;
  }

  const docId = state.currentDocId;
  const history = state.qaHistory[docId] || [];

  const suggestedQuestions = [
    'What sensitive data exists in this document?',
    'What is the risk level of this document and why?',
    'Summarize this document.',
    'Are there any exposed API keys or credentials?'
  ];

  content.innerHTML = `
    <div class="chat-suggestions">
      ${suggestedQuestions.map(q => `
        <button class="chat-suggestion" onclick="submitQuestion('${escapeHtml(q)}')">${q}</button>
      `).join('')}
    </div>

    <div class="chat-window">
      <div class="chat-messages" id="chat-messages-container">
        ${history.map(msg => `
          <div class="chat-msg ${msg.role}">
            <div>${escapeHtml(msg.text).replace(/\n/g, '<br>')}</div>
            <div class="chat-meta">${msg.timestamp}</div>
          </div>
        `).join('') || '<div class="text-muted text-sm text-center" style="margin-top:2rem;">Ask a question about the document content.</div>'}
      </div>
      <div class="chat-input-bar">
        <input type="text" id="chat-input-field" class="chat-input" placeholder="Ask anything about the document…" autocomplete="off" />
        <button class="chat-send" id="chat-send-btn" onclick="submitChatInput()">Send</button>
      </div>
    </div>

    ${history.length > 0 ? `
      <div class="row" style="gap:0.5rem; margin-top:0.75rem;">
        <button class="btn btn-outline btn-sm" onclick="clearChat()">Clear chat</button>
      </div>
    ` : ''}
  `;

  // Bind Enter key press
  const input = document.getElementById('chat-input-field');
  if (input) {
    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') submitChatInput();
    });
  }

  // Scroll chat messages to bottom
  const container = document.getElementById('chat-messages-container');
  if (container) {
    container.scrollTop = container.scrollHeight;
  }
}

async function submitQuestion(question) {
  const docId = state.currentDocId;
  if (!docId) return;

  if (!state.qaHistory[docId]) {
    state.qaHistory[docId] = [];
  }

  const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  // Push User message
  state.qaHistory[docId].push({ role: 'user', text: question, timestamp });
  renderQAPage();

  try {
    const res = await window.api.askQuestion(docId, question, state.apiKey);
    state.qaHistory[docId].push({
      role: 'assistant',
      text: res.answer,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    });
    renderQAPage();
  } catch (err) {
    state.qaHistory[docId].push({
      role: 'assistant',
      text: 'Error processing query. Make sure Groq is available or check key.',
      timestamp
    });
    renderQAPage();
  }
}

function submitChatInput() {
  const input = document.getElementById('chat-input-field');
  if (!input) return;
  const question = input.value.trim();
  if (!question) return;

  submitQuestion(question);
}

function clearChat() {
  const docId = state.currentDocId;
  if (docId) {
    state.qaHistory[docId] = [];
    renderQAPage();
  }
}

// ── 5. Reports Page View ──────────────────────────────────────────
let activeReportText = '';

function renderReportsPage() {
  renderDocSelector('reports-doc-selector', 'reports-doc-select');

  const content = document.getElementById('reports-content');
  if (!content) return;

  if (!state.currentDocDetails) {
    content.innerHTML = `<div class="empty-state">No documents analyzed yet. <a href="#upload" onclick="navigate('upload')">Upload one →</a></div>`;
    return;
  }

  const doc = state.currentDocDetails;
  const rp = doc.risk_profile;
  const theme = RISK_THEMES[doc.risk_level] || RISK_THEMES.LOW;

  // Compile quick checklist items
  const checks = [
    { label: 'Exposed plain text credentials', passed: !doc.detections.some(d => (d.pattern_name || '').includes('key') || (d.pattern_name || '').includes('password')) },
    { label: 'Plain text government identifiers (PAN/Aadhaar)', passed: !doc.detections.some(d => ['aadhaar', 'pan'].includes(d.pattern_name || '')) },
    { label: 'Exposed credit card primary account numbers', passed: !doc.detections.some(d => (d.pattern_name || '').includes('credit_card')) },
    { label: 'GDPR / DPDP regulation violations', passed: rp.dpdp_violations.length === 0 && rp.gdpr_violations.length === 0 },
    { label: 'Overall document risk rating is acceptable', passed: ['LOW', 'MEDIUM'].includes(doc.risk_level) }
  ];

  content.innerHTML = `
    <!-- Top Meta cards -->
    <div class="row" style="gap:1rem; margin-bottom:1.5rem; align-items:stretch;">
      <div class="col" style="border:1px solid #E8E8E8; border-radius:8px; padding:1rem;">
        <div class="section-label">Overall Risk</div>
        <span class="badge ${theme.borderClass}">${doc.risk_level}</span>
      </div>
      <div class="col" style="border:1px solid #E8E8E8; border-radius:8px; padding:1rem;">
        <div class="section-label">Findings</div>
        <div style="font-size:1.15rem; font-weight:700; color:#111111;">${doc.detection_count} detected</div>
      </div>
      <div class="col" style="border:1px solid #E8E8E8; border-radius:8px; padding:1rem;">
        <div class="section-label">Scan Context</div>
        <div style="font-size:0.83rem; color:#555555; font-weight:500;">${doc.filename}</div>
      </div>
    </div>

    <button class="btn btn-primary" id="btn-generate-report" onclick="triggerReportGeneration()">
      Generate AI compliance summary
    </button>

    <div id="report-view-container" class="hidden">
      <div class="report-box" id="report-text-area"></div>
      <div class="row mt-1" style="gap:0.5rem;">
        <button class="btn btn-outline btn-sm" onclick="downloadReportTxt()">Download TXT</button>
        <button class="btn btn-outline btn-sm" onclick="downloadReportPdf()">Download PDF</button>
      </div>
    </div>

    <div class="section-label" style="margin-top:2rem;">Compliance Checklist</div>
    <div class="checklist">
      ${checks.map(c => `
        <div class="check-item" style="background:${c.passed ? '#FFFFFF' : '#FFF8F8'};">
          <span class="check-mark ${c.passed ? 'check-pass' : 'check-fail'}">
            ${c.passed ? '✓' : '✗'}
          </span>
          <span class="check-label" style="color:${c.passed ? '#444444' : '#991B1B'};">
            ${c.label}
          </span>
        </div>
      `).join('')}
    </div>
  `;

  // Restore active report text if available
  if (activeReportText) {
    const c = document.getElementById('report-view-container');
    const a = document.getElementById('report-text-area');
    if (c && a) {
      c.classList.remove('hidden');
      a.textContent = activeReportText;
    }
  }
}

async function triggerReportGeneration() {
  const btn = document.getElementById('btn-generate-report');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Generating AI compliance report…';
  }

  try {
    const res = await window.api.generateReport(state.currentDocId, state.apiKey);
    activeReportText = res.report;
    renderReportsPage();
    showToast('AI report successfully compiled.');
  } catch (err) {
    showToast('Failed to generate compliance report. Check API Key.', true);
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Generate AI compliance summary';
    }
  }
}

function downloadReportTxt() {
  if (!activeReportText) return;
  const doc = state.currentDocDetails;
  const blob = new Blob([activeReportText], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${doc ? doc.filename : 'document'}_compliance_report.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

async function downloadReportPdf() {
  if (!activeReportText) return;
  const doc = state.currentDocDetails;
  try {
    showToast('Compiling PDF report...');
    const blob = await window.api.downloadPdfReport(state.currentDocId, activeReportText);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${doc ? doc.filename : 'document'}_compliance_report.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showToast('PDF download complete.');
  } catch (err) {
    showToast('Failed to compile PDF report', true);
  }
}

// Local search state for audit logs
let auditSearchQuery = '';

async function renderAuditPage() {
  const content = document.getElementById('audit-content');
  if (!content) return;

  try {
    const res = await window.api.getAudit();
    state.auditLogs = res.events;
    state.auditStats = res.stats;

    const stats = state.auditStats;
    const evCounts = stats.by_event_type || {};

    // Filter audit logs based on search query
    const filteredLogs = state.auditLogs.filter(log => {
      const q = auditSearchQuery.toLowerCase();
      const matchDoc = (log.filename || '').toLowerCase().includes(q);
      const matchAction = (log.event_type || '').toLowerCase().includes(q);
      const matchStatus = (log.status || '').toLowerCase().includes(q);
      const matchRisk = (log.risk_level || '').toLowerCase().includes(q);
      return matchDoc || matchAction || matchStatus || matchRisk;
    });

    content.innerHTML = `
      <div class="row" style="gap:1rem; margin-bottom:1.5rem; align-items:stretch;">
        <div class="col" style="border:1px solid #E8E8E8; border-radius:8px; padding:1rem; text-align:center;">
          <div class="section-label">Total Events</div>
          <div style="font-size:1.5rem; font-weight:700; color:#111111;">${stats.total_events || 0}</div>
        </div>
        <div class="col" style="border:1px solid #E8E8E8; border-radius:8px; padding:1rem; text-align:center;">
          <div class="section-label">Scans</div>
          <div style="font-size:1.5rem; font-weight:700; color:#111111;">${evCounts.SCAN_COMPLETE || 0}</div>
        </div>
        <div class="col" style="border:1px solid #E8E8E8; border-radius:8px; padding:1rem; text-align:center;">
          <div class="section-label">Q&amp;A Queries</div>
          <div style="font-size:1.5rem; font-weight:700; color:#111111;">${evCounts.QA_QUERY || 0}</div>
        </div>
        <div class="col" style="border:1px solid #E8E8E8; border-radius:8px; padding:1rem; text-align:center;">
          <div class="section-label">Redactions</div>
          <div style="font-size:1.5rem; font-weight:700; color:#111111;">${evCounts.REDACTION_APPLIED || 0}</div>
        </div>
      </div>

      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem; flex-wrap:wrap; gap:0.5rem;">
        <div class="section-label" style="margin-bottom:0;">Timeline Ledger</div>
        <input 
          type="text" 
          id="audit-search-field" 
          placeholder="Search logs…" 
          value="${escapeHtml(auditSearchQuery)}" 
          style="padding:6px 10px; border:1px solid #DDDDDD; border-radius:6px; font-size:0.78rem; width:220px; outline:none;" 
        />
      </div>

      <div style="border:1px solid #E8E8E8; border-radius:8px; overflow-x:auto; background:#FFFFFF;">
        <table class="audit-table">
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Action</th>
              <th>Document</th>
              <th>Risk</th>
              <th>Findings</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${filteredLogs.map(log => `
              <tr>
                <td>${log.timestamp}</td>
                <td><strong>${log.event_type}</strong></td>
                <td>${log.filename || '—'}</td>
                <td>${log.risk_level ? `<span class="badge ${RISK_THEMES[log.risk_level]?.borderClass || ''}">${log.risk_level}</span>` : '—'}</td>
                <td>${log.detection_count !== null ? log.detection_count : '—'}</td>
                <td>
                  <span style="color:${log.status === 'SUCCESS' ? '#16A34A' : '#DC2626'}; font-weight:600;">
                    ${log.status}
                  </span>
                </td>
              </tr>
            `).join('') || '<tr><td colspan="6" class="text-center text-muted" style="padding:1.5rem;">No actions matched the search criteria.</td></tr>'}
          </tbody>
        </table>
      </div>
    `;

    // Bind search event
    const searchField = document.getElementById('audit-search-field');
    if (searchField) {
      searchField.addEventListener('input', (e) => {
        auditSearchQuery = e.target.value;
        // Keep focus by rendering without clearing input cursor
        const q = auditSearchQuery.toLowerCase();
        const rows = document.querySelectorAll('.audit-table tbody tr');
        let matchCount = 0;
        
        state.auditLogs.forEach((log, idx) => {
          const matchDoc = (log.filename || '').toLowerCase().includes(q);
          const matchAction = (log.event_type || '').toLowerCase().includes(q);
          const matchStatus = (log.status || '').toLowerCase().includes(q);
          const matchRisk = (log.risk_level || '').toLowerCase().includes(q);
          const isMatch = matchDoc || matchAction || matchStatus || matchRisk;
          
          if (rows[idx]) {
            rows[idx].classList.toggle('hidden', !isMatch);
            if (isMatch) matchCount++;
          }
        });
      });
    }
  } catch (err) {
    content.innerHTML = `<div class="empty-state error">Failed to load audit logs.</div>`;
  }
}

// ── Helpers ───────────────────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
