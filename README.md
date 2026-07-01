<div align="center">

# 🛡️ DataGuard AI
### Sensitive Data Detection & Compliance Assistant

*Built for the Proteccio Data AI Innovation Internship Challenge*

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35-FF4B4B?logo=streamlit)](https://streamlit.io)
[![Gemini](https://img.shields.io/badge/Google-Gemini%201.5%20Flash-4285F4?logo=google)](https://aistudio.google.com)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-RAG%20Pipeline-orange)](https://www.trychroma.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

</div>

---

## 📌 Overview

**DataGuard AI** is a full-stack AI-powered application that detects sensitive/confidential information in uploaded documents, classifies risk levels, maps violations to compliance frameworks (India DPDP Act 2023 & GDPR), and provides an intelligent Q&A interface powered by RAG (Retrieval-Augmented Generation).

> **This is not a minimum-viable product.** It is designed to demonstrate genuine engineering depth, AI/ML understanding, and practical security thinking.

---

## ✨ Key Features

| Feature | Details |
|---------|---------|
| 📤 **Multi-format Upload** | PDF, TXT, CSV, DOCX with OCR fallback |
| 🔍 **20+ Detection Patterns** | Aadhaar, PAN, Credit Cards, API Keys, Bank Details, GST, IFSC, UPI, Passports, and more |
| ✅ **Smart Validation** | Luhn algorithm for credit cards, Aadhaar digit rules |
| 📊 **4-Level Risk Classification** | CRITICAL / HIGH / MEDIUM / LOW with weighted scoring |
| ⚖️ **Compliance Mapping** | India DPDP Act 2023 + GDPR Article mapping |
| 🤖 **AI-Powered Analysis** | Google Gemini 1.5 Flash for compliance summaries |
| 💬 **RAG Q&A** | ChromaDB + sentence-transformers for accurate document Q&A |
| 🎭 **Data Redaction** | Full / partial / hash redaction modes with download |
| 📑 **PDF Reports** | Professional compliance reports via ReportLab |
| 📋 **Audit Logging** | SQLite-based audit trail with timeline visualization |
| 📁 **Multi-document** | Analyze and compare multiple documents simultaneously |
| 🐳 **Docker Ready** | One-command deployment |

---

## 🚀 Setup Instructions

### Prerequisites

- Python 3.9 or higher
- pip
- (Optional) Google Gemini API key — [get it free here](https://aistudio.google.com/)
- (Optional) Tesseract OCR — for scanned PDF support

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/sensitive-data-detection.git
cd sensitive-data-detection
```

### 2. Create Virtual Environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

> **Note:** `en_core_web_sm` (spaCy model) is included in `requirements.txt` and will be installed automatically.
> If it fails, run: `python -m spacy download en_core_web_sm`

### 4. Configure Environment

```bash
cp .env.example .env
# Edit .env and add your Gemini API key
```

```env
GEMINI_API_KEY=your_api_key_here
```

### 5. Run the Application

```bash
streamlit run app.py
```

Open your browser at `http://localhost:8501`

---

### 🐳 Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up --build

# Or run directly
docker build -t dataguard-ai .
docker run -p 8501:8501 -e GEMINI_API_KEY=your_key dataguard-ai
```

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      Streamlit Frontend                          │
│         Multi-page app · Dark theme · Plotly charts             │
│                                                                   │
│  🏠 Home  📤 Upload  🔍 Detection  📊 Dashboard                  │
│  💬 Q&A   📝 Reports  📋 Audit Log                               │
└───────────────────────┬─────────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────────┐
│                      Core Engine Layer                           │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  Document    │  │  Detection   │  │  Risk Classifier      │  │
│  │  Processor   │  │  Engine      │  │  (DPDP + GDPR maps)  │  │
│  │  PDF/TXT/    │  │  20+ regex   │  │  4-level scoring     │  │
│  │  CSV/DOCX+   │  │  + spaCy NLP │  │  Compliance reports  │  │
│  │  OCR         │  │  Luhn check  │  │                       │  │
│  └──────────────┘  └──────────────┘  └───────────────────────┘  │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  AI Engine   │  │  RAG Engine  │  │  Redactor             │  │
│  │  Gemini 1.5  │  │  ChromaDB +  │  │  Full/Partial/Hash   │  │
│  │  Flash       │  │  MiniLM-L6   │  │  HTML highlight      │  │
│  │  + fallback  │  │  embeddings  │  │  Download export     │  │
│  └──────────────┘  └──────────────┘  └───────────────────────┘  │
│                                                                   │
│  ┌──────────────┐  ┌────────────────────────────────────────┐    │
│  │  Audit       │  │  Utils: PDF reports, CSV/JSON export   │    │
│  │  Logger      │  │  session management, helper functions  │    │
│  │  (SQLite)    │  │                                         │    │
│  └──────────────┘  └────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🧠 AI/ML Approach

### 1. Sensitive Data Detection (Regex + NLP)

**Layer 1 — Regex Patterns:**  
20+ hand-crafted patterns with context-aware matching:
- Aadhaar: `\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b`
- PAN: `\b[A-Z]{5}[0-9]{4}[A-Z]\b`
- Credit Card (Luhn-validated): Visa, MasterCard, AMEX patterns
- API Keys: Context-sensitive pattern matching on labeled fields
- IFSC, GST, UPI, SWIFT, Passport, Vehicle Registration, etc.

**Layer 2 — Validation:**
- **Luhn Algorithm** for credit card number validation
- **Aadhaar digit rules** (must start 2–9, be 12 digits)
- Confidence score adjustment based on validation results

**Layer 3 — spaCy NLP:**
- Named Entity Recognition (PERSON, ORG) enhances detection confidence
- Contextual boosting for detections near named entities
- Graceful fallback when spaCy model unavailable

### 2. Risk Classification

Weighted scoring system:
```
Score = (Critical × 25) + (High × 12) + (Medium × 5) + (Low × 1)
      + Dangerous Combination Penalties
      + Count Threshold Penalties
```

Dangerous Combination Bonuses:
- Aadhaar + Financial data: +30 points
- Credentials/API keys: +25 points
- Multiple critical findings: +20 points

Final classification:
- Score ≥ 70 OR any CRITICAL detection → **CRITICAL**
- Score ≥ 40 OR ≥3 HIGH detections → **HIGH**
- Score ≥ 15 OR ≥2 MEDIUM detections → **MEDIUM**
- Otherwise → **LOW**

### 3. RAG Pipeline (Q&A)

```
User Query → Sentence Embedding (all-MiniLM-L6-v2)
           → Cosine Similarity Search (ChromaDB)
           → Top-K Relevant Chunks Retrieved
           → Gemini 1.5 Flash (with chunk context + detection data)
           → Grounded, Accurate Answer
```

- **Chunking**: Paragraph-aware splitting with 64-character overlap
- **Embeddings**: `sentence-transformers/all-MiniLM-L6-v2` (384-dim)
- **Vector DB**: ChromaDB (in-memory, instant startup)
- **Generation**: Gemini 1.5 Flash with custom system prompts
- **Fallback**: Rule-based engine for common queries (no API key needed)

### 4. Compliance Framework Mapping

Each detection type is mapped to:
- **India DPDP Act 2023** sections (Section 3, 7, etc.)
- **GDPR Articles** (Art. 4, 9, 32, etc.)

This enables automatic identification of regulatory exposure.

---

## ⚠️ Challenges Faced

### 1. Pattern False Positives
**Challenge**: Generic regex patterns (phone, ID) produce many false positives.  
**Solution**: Multi-layer approach — regex narrows candidates, validators (Luhn, Aadhaar rules) filter invalid matches, and confidence scoring provides a clear quality signal.

### 2. Overlapping Detections
**Challenge**: A single text span can match multiple patterns (e.g., a 16-digit number matching both phone and credit card patterns).  
**Solution**: Position-aware deduplication that keeps the highest-confidence detection when patterns overlap.

### 3. RAG Without External Hosting
**Challenge**: Maintaining vector DB state in Streamlit's stateless architecture.  
**Solution**: ChromaDB in-memory mode with session state caching of doc IDs. Fast re-indexing on document upload.

### 4. Graceful Degradation
**Challenge**: Not all users have Gemini API keys, spaCy, or Tesseract installed.  
**Solution**: Every AI/NLP component has a fallback — rule-based summaries, regex-only detection, and text extraction alternatives.

### 5. Large Document Performance
**Challenge**: Processing large PDFs with many detections is slow.  
**Solution**: Chunked text processing, limited preview (5,000 chars) in UI, cached detection results in session state.

---

## 🔮 Future Improvements

1. **Production Vector DB**: Replace in-memory ChromaDB with persistent Qdrant or Weaviate
2. **Fine-tuned Detection Model**: Train a Named Entity Recognition model specifically for Indian PII types
3. **OCR Enhancement**: Multi-language OCR support (Hindi, regional languages)
4. **Real-time Monitoring**: WebSocket-based scanning for live document streams
5. **Cloud Integration**: AWS Textract, Google Document AI for enterprise-grade extraction
6. **Role-Based Access Control**: Multi-user support with different permission levels
7. **Workflow Integration**: API endpoints for CI/CD pipeline scanning
8. **Advanced Redaction**: PDF-native redaction (not just text replacement)
9. **Anomaly Detection**: ML model to detect novel sensitive data patterns
10. **Compliance Templates**: Pre-built templates for ISO 27001, SOC 2, HIPAA, PCI-DSS

---

## 📁 Project Structure

```
Sensitive Data Detection/
├── app.py                          # Main Streamlit entry point (landing page)
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment variable template
├── Dockerfile                      # Docker containerization
├── docker-compose.yml              # Docker Compose configuration
├── README.md                       # This file
│
├── core/                           # Core business logic
│   ├── document_processor.py       # PDF/TXT/CSV/DOCX extraction + OCR
│   ├── detection_engine.py         # 20+ regex patterns + spaCy NLP
│   ├── risk_classifier.py          # Risk scoring + DPDP/GDPR mapping
│   ├── ai_engine.py                # Gemini API + fallback
│   ├── rag_engine.py               # ChromaDB RAG pipeline
│   ├── redactor.py                 # Data masking + HTML highlighting
│   └── audit_logger.py             # SQLite audit trail
│
├── pages/                          # Streamlit multi-page app
│   ├── 01_📤_Upload.py             # Document upload & initial analysis
│   ├── 02_🔍_Detection.py          # Detection results, filtering, redaction
│   ├── 03_📊_Dashboard.py          # Plotly risk charts & compliance maps
│   ├── 04_💬_QnA.py                # RAG-powered chat interface
│   ├── 05_📝_Reports.py            # AI compliance reports + PDF export
│   └── 06_📋_Audit_Log.py          # Audit trail viewer + export
│
├── utils/
│   └── helpers.py                  # Session management, exports, PDF gen
│
├── assets/
│   └── styles.css                  # Premium dark theme CSS
│
├── sample_docs/
│   ├── sample_sensitive.txt        # High-risk sample (text)
│   └── sample_hr_data.csv          # HR data sample (CSV)
│
└── tests/
    └── test_detection.py           # pytest unit tests
```

---

## 🧪 Running Tests

```bash
pytest tests/test_detection.py -v
```

---

## 🔒 Security & Privacy Notes

- All document processing happens **locally** — no data is sent to external servers except the Gemini API (only relevant text snippets in prompts)
- Audit logs are stored locally in SQLite
- Uploaded documents are held only in session memory and cleared on session end
- The app never writes document content to disk unless the user explicitly downloads a report

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
Built with ❤️ for the Proteccio Data AI Innovation Internship · July 2026
</div>
