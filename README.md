<div align="center">

# ⚔️ DataGuard AI
### Sensitive Data Detection & Compliance Assistant


[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111.0-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![Groq](https://img.shields.io/badge/Groq-Llama--3.1--8b--instant-orange)](https://groq.com)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-RAG%20Pipeline-orange)](https://www.trychroma.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

</div>

---

## 📌 Overview

**DataGuard AI** is a secure, high-performance web application designed to detect sensitive/confidential information in uploaded documents, classify overall compliance risk, map violations to modern frameworks (India DPDP Act 2023 & GDPR), and provide an interactive RAG (Retrieval-Augmented Generation) Q&A console.

The application features a clean, professional, and minimalist human-designed black-and-white theme, combining a lightweight **Vanilla HTML/JS Single Page Application (SPA)** with a high-performance **FastAPI backend** running on a unified port.

> **This is not a minimum-viable product.** It is designed to demonstrate production-grade software architecture, advanced NLP detection, active regex filtering validators, and robust AI privacy controls.

---

## ✨ Key Features

| Feature | Details |
|---------|---------|
| 📤 **Multi-format Upload** | PDF, TXT, CSV, DOCX text extraction with automated OCR fallback |
| 🔍 **20+ Detection Patterns** | Aadhaar, PAN, Credit Cards, API Keys, Passwords, Bank Details, GST, IFSC, UPI, Passports, and more |
| ✅ **Smart Validation** | Luhn algorithm validation, Aadhaar digit constraints, and SWIFT/BIC ISO country code validation to eliminate false positives on uppercase last names |
| 📊 **4-Level Risk Classification** | CRITICAL / HIGH / MEDIUM / LOW using a custom priority-based taxonomy |
| ⚖️ **Compliance Mapping** | Section mappings to India DPDP Act 2023 & EU GDPR Articles |
| 🤖 **AI-Powered Analysis** | Groq (`llama-3.1-8b-instant`) for secure compliance summaries and Q&A (requires `gsk_` key) |
| 💬 **RAG Q&A Console** | ChromaDB + sentence-transformers for localized document context Q&A |
| 🛡️ **Privacy Masking** | System-enforced AI response filtering to guarantee that unmasked PII values never leak in chat |
| 🎭 **Data Redaction** | Fully interactive Redaction tab supporting Full / Partial / Hash redactions |
| 📑 **PDF Reports** | Downloadable professional compliance reports compiled via ReportLab |
| 📋 **Audit Log Ledger** | SQLite-backed timeline ledger with dynamic search filters |
| 🐳 **Docker Deployment** | Dockerfile and compose file for one-command deployment |

---

## 🚀 Setup Instructions

### Prerequisites

- Python 3.9 or higher
- pip
- (Optional) Groq API Key — [get your API key here](https://console.groq.com/)
- (Optional) Tesseract OCR — for scanned image/PDF OCR fallback

### 1. Clone the Repository

```bash
git clone https://github.com/rishikroyal/dataguard.git
cd dataguard
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

> **Note:** The spaCy `en_core_web_sm` model will be downloaded automatically during package installation. If it fails, run: `python -m spacy download en_core_web_sm`

### 4. Configure Environment

Rename `.env.example` to `.env` and configure your credentials:

```bash
cp .env.example .env
```

```env
GROQ_API_KEY=gsk_your_groq_key_here
```

### 5. Run the Application

Start the FastAPI application server:

```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Open your browser at **`http://localhost:8000`**

---

### 🐳 Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up --build

# Or run directly via Docker CLI
docker build -t dataguard-ai .
docker run -p 8000:8000 -e GROQ_API_KEY=gsk_key dataguard-ai
```

---

### 🌐 Deploying to Render (Recommended)

Since this project already contains a configured `Dockerfile` that automatically handles Tesseract OCR and system libraries, deploying via **Docker** on [Render](https://render.com/) is the easiest and most reliable method:

1. **Push your code** to your GitHub repository (e.g. `https://github.com/rishikroyal/dataguard`).
2. **Log in to Render** and click **New +** -> **Web Service**.
3. **Connect your repository** from GitHub.
4. **Configure Settings**:
   * **Name**: `dataguard-ai`
   * **Runtime**: Select **Docker** (Render will automatically detect the `Dockerfile` in the root).
   * **Instance Type**: **Free** (or any tier).
5. **Add Environment Variables**:
   * Click on the **Advanced** section.
   * Add a new environment variable:
     * Key: `GROQ_API_KEY`
     * Value: `gsk_your_actual_groq_key_here`
6. Click **Deploy Web Service**. Render will build the container, install system dependencies, and deploy the application on a public URL.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Vanilla HTML/JS Frontend                     │
│         Minimalist B&W SPA · Real-time charts · Search Filters   │
│                                                                 │
│   Home  ·  Upload  ·  Detection  ·  Dashboard  ·  Q&A  ·  Audit  │
└───────────────────────┬─────────────────────────────────────────┘
                        │ API calls served on Port 8000
┌───────────────────────▼─────────────────────────────────────────┐
│                      FastAPI Backend App                        │
│         Router Layer · Static Asset Serving · SQLite Store       │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  Document    │  │  Detection   │  │  Risk Classifier      │  │
│  │  Processor   │  │  Engine      │  │  Custom Priority-     │  │
│  │  PDF/TXT/    │  │  20+ regex   │  │  Based Risk Model     │  │
│  │  CSV/DOCX +  │  │  + spaCy NLP │  │  (DPDP + GDPR maps)   │  │
│  │  Tesseract   │  │  Luhn Check  │  │                       │  │
│  └──────────────┘  └──────────────┘  └───────────────────────┘  │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  AI Engine   │  │  RAG Engine  │  │  Redactor             │  │
│  │  Groq Llama  │  │  ChromaDB +  │  │  Full/Partial/Hash    │  │
│  │  3.1 Flash   │  │  MiniLM-L6   │  │  HTML highlight       │  │
│  │  + fallback  │  │  embeddings  │  │  Download export      │  │
│  └──────────────┘  └──────────────┘  └───────────────────────┘  │
│                                                                 │
│  ┌──────────────┐  ┌────────────────────────────────────────┐    │
│  │  Audit       │  │  Utils: PDF report generation,         │    │
│  │  Logger      │  │  session management, export helpers    │    │
│  │  (SQLite)    │  │                                         │    │
│  └──────────────┘  └────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🧠 AI/ML Approach

### 1. Sensitive Data Detection (Regex + NLP)

* **Layer 1 — Regex Patterns:** 20+ fine-tuned patterns covering Aadhaar, PAN, Passports, Voter IDs, Credit Cards, GSTIN, IFSC, UPI, and technical configurations (API Keys, Passwords).
* **Layer 2 — Hard Validation Filters:**
  * **Luhn Algorithm Check** to validate credit cards.
  * **Aadhaar rules** (must start 2-9 and pass checksum).
  * **SWIFT ISO Country Code Validation**: Validates that characters 5 & 6 represent an official ISO-3166-1 country code (e.g. `IN`, `US`, `GB`). This prevents uppercase names (such as `UPPARAPALLI`) from triggering false positives.
* **Layer 3 — spaCy Named Entity Recognition (NER)**: Evaluates named entities (`PERSON`, `ORG`) near pattern matches to dynamically adjust detection confidence.

### 2. Custom Taxonomy Risk Classification

The engine uses a strict category priority risk model:
* **🚨 Critical**: Passwords, API Keys, Encryption Keys, Digital Certificates, Military/Defense documents, or documents containing *both* a sensitive ID (Aadhaar, PAN, Passport, DL) and a credential.
* **🔴 High**: Aadhaar, Passport, PAN, Driving Licence, Voter ID, Tax IDs, Government employee IDs, or internal documents containing "Internal".
* **🟡 Medium**: Government employee details, department/ministry names, office addresses, or government-issued document references without PII.
* **🟢 Low**: Public notices, public regulations, ministry press releases, or public government websites.

### 3. RAG Pipeline (Q&A)

```
User Query → Sentence Embedding (all-MiniLM-L6-v2)
           → Cosine Similarity Search (ChromaDB)
           → Top-K Relevant Document Chunks Retrieved
           → System Prompt (Exclusion of unmasked PII values)
           → Groq (llama-3.1-8b-instant LLM response)
           → Answer rendered with local compliance fallback
```

---

## 🔒 Security & Privacy Notes

* **Local processing by default**: All parsing, text extraction, validation, and redaction are performed locally on your device.
* **API Isolation**: The only data transmitted externally is the local chunk data matching your direct Q&A queries to the Groq API (no raw file text is sent).
* **PII Leakage Prevention**: AI system prompts restrict the LLM from outputting unmasked personal details. Even if the RAG context contains raw PII, the engine enforces compliance fallback masking in its responses.

---



---

<div align="center">
</div>
