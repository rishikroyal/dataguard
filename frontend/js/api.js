/**
 * DataGuard AI — API Client
 * Wraps all REST API interactions with the FastAPI backend.
 */

const API_BASE = '/api';

window.api = {
  /**
   * Check API health
   */
  async checkHealth() {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error('Health check failed');
    return res.json();
  },

  /**
   * Upload a document for analysis
   * @param {File} file 
   * @param {boolean} useOcr 
   * @param {string} apiKey 
   */
  async uploadDocument(file, useOcr = false, apiKey = '') {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('use_ocr', useOcr);
    formData.append('api_key', apiKey);

    const res = await fetch(`${API_BASE}/upload`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
      throw new Error(err.detail || 'Upload failed');
    }
    return res.json();
  },

  /**
   * List all analyzed documents
   */
  async listDocuments() {
    const res = await fetch(`${API_BASE}/documents`);
    if (!res.ok) throw new Error('Failed to list documents');
    return res.json();
  },

  /**
   * Get document metadata, detections, and risk profile
   */
  async getDocument(docId) {
    const res = await fetch(`${API_BASE}/documents/${docId}`);
    if (!res.ok) throw new Error('Failed to fetch document details');
    return res.json();
  },

  /**
   * Ask a question about a document (RAG)
   */
  async askQuestion(docId, question, apiKey = '') {
    const res = await fetch(`${API_BASE}/qa`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ doc_id: docId, question, api_key: apiKey }),
    });
    if (!res.ok) throw new Error('Failed to get answer');
    return res.json();
  },

  /**
   * Generate AI compliance report
   */
  async generateReport(docId, apiKey = '') {
    const res = await fetch(`${API_BASE}/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ doc_id: docId, api_key: apiKey }),
    });
    if (!res.ok) throw new Error('Failed to generate report');
    return res.json();
  },

  /**
   * Download the PDF report
   */
  async downloadPdfReport(docId, summary) {
    const res = await fetch(`${API_BASE}/report/pdf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ doc_id: docId, summary }),
    });
    if (!res.ok) throw new Error('Failed to generate PDF report');
    return res.blob();
  },

  /**
   * Apply redaction to document text
   * @param {string} docId 
   * @param {string} mode - full | partial | hash
   */
  async redactDocument(docId, mode = 'partial') {
    const res = await fetch(`${API_BASE}/redact`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ doc_id: docId, mode }),
    });
    if (!res.ok) throw new Error('Failed to redact document');
    return res.json();
  },

  /**
   * Fetch recent audit logs and stats
   */
  async getAudit() {
    const res = await fetch(`${API_BASE}/audit`);
    if (!res.ok) throw new Error('Failed to fetch audit logs');
    return res.json();
  },

  /**
   * Trigger server-side sample document processing
   * @param {string} name - sensitive | hr_csv
   */
  async loadSample(name) {
    const res = await fetch(`${API_BASE}/sample/${name}`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Failed to load sample');
    return res.json();
  }
};
