# ⚔️ DataGuard AI
### Enterprise-Grade Sensitive Data Detection & Compliance Assistant

> **Internship Challenge Submission**: Developed for the *Proteccio Data AI Innovation Internship Challenge* (July 2026).  
> 🔗 **Live Working Prototype**: [https://dataguard-ai.onrender.com](https://dataguard-ai.onrender.com)  
> ⚠️ *Note: Render free tier resources are near exhaustion. If the live instance is slow to respond or spinning up, please consider this hosting limitation or deploy it locally using the Docker instructions below.*

---

## 📌 Executive Summary

**DataGuard AI** is a secure, high-performance web application designed to scan enterprise documents, identify sensitive information (PII, Financials, Credentials), map compliance violations to regulatory frameworks (India DPDP Act 2023 & EU GDPR), and facilitate secure, context-grounded Q&A over the documents without leaking confidential details.

This project was built to demonstrate **production-grade engineering depth**, moving far beyond a minimum viable product. It showcases a modern **FastAPI backend** paired with a minimalist, high-fidelity **Vanilla HTML/CSS/JS Single Page Application (SPA)**, active regex heuristics with deterministic validators, local semantic embeddings with vector databases (RAG), and secure LLM post-processing.

---

## 🏗️ Architecture & System Design

DataGuard AI utilizes a single-port, lightweight decoupled architecture where FastAPI serves both high-concurrency API endpoints and compiled static assets.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Vanilla HTML/JS Frontend                     │
│      Minimalist black & white SPA · Real-time Plotly charts     │
│                                                                 │
│   Home  ·  Upload  ·  Detection  ·  Dashboard  ·  Q&A  ·  Audit  │
└───────────────────────┬─────────────────────────────────────────┘
                        │ HTTP APIs / JSON Responses
┌───────────────────────▼─────────────────────────────────────────┐
│                    FastAPI Server App (Port 8000)               │
│         Router Layer · Static Asset Serving · SQLite Ledger      │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  Document    │  │  Detection   │  │  Risk Classifier      │  │
│  │  Processor   │  │  Engine      │  │  Rule-based priority  │  │
│  │  PDF/TXT/    │  │  20+ Heuristics│  │  risk scoring matrix  │  │
│  │  CSV/DOCX +  │  │  + spaCy NER │  │  (DPDP + GDPR maps)   │  │
│  │  Tesseract   │  │  Luhn checks │  │                       │  │
│  └──────────────┘  └──────────────┘  └───────────────────────┘  │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  AI Engine   │  │  RAG Engine  │  │  Redactor             │  │
│  │  Groq Client │  │  ChromaDB +  │  │  Full / Partial /     │  │
│  │  (Llama 3.1) │  │  MiniLM-L6   │  │  Hash Masking         │  │
│  │  + Fallbacks │  │  vector index│  │  HTML highlight       │  │
│  └──────────────┘  └──────────────┘  └───────────────────────┘  │
│                                                                 │
│  ┌──────────────┐  ┌────────────────────────────────────────┐    │
│  │  Audit       │  │  Utils: ReportLab PDF compiler,        │    │
│  │  Logger      │  │  session management, export helpers    │    │
│  │  (SQLite)    │  │                                         │    │
│  └──────────────┘  └────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Technical Highlights of the Stack:
* **Backend API**: **FastAPI** for asynchronous routing, request validation via Pydantic, and high throughput.
* **Frontend SPA**: Written entirely in **Vanilla HTML5, Javascript (ES6+), and CSS3** (No heavy frontend build chains or frameworks like React/Next.js). It loads in milliseconds, communicates via asynchronous `fetch` calls, and renders clean layouts with a tailored, developer-first aesthetic.
* **Database Ledger**: **SQLite** serves as a lightweight, transaction-safe audit logging ledger.
* **Telemetry & Storage Isolation**: Completely offline by design. All parsing, document storage, and ledger logging run on local disks, keeping candidate files secure.

---

## 🧠 AI/ML & Natural Language Processing Approach

The pipeline combines deterministic heuristics, machine learning classifiers, and generative AI to maximize precision and recall.

### 1. Multi-Layer Sensitive Data Detection
* **Layer 1 — Regular Expressions**: 20+ custom-built regex patterns targeting identifiers such as Aadhaar cards, PAN cards, Passports, Driving Licences, Credit Cards (Visa, MC, Amex), GSTIN, IFSC, technical API Keys, and passwords.
* **Layer 2 — Deterministic Validators**:
  * **Luhn Algorithm Checksum** for verifying valid credit card numbers.
  * **Aadhaar constraint check** (detects invalid starting digits and lengths).
  * **SWIFT ISO Country Code Check**: Validates that characters 5 & 6 match official country codes (e.g. `IN`, `US`, `GB`). This prevents uppercase names (such as `UPPARAPALLI`) from triggering false positives.
* **Layer 3 — NLP Context Boosting**: Uses a **spaCy** Named Entity Recognition (NER) model to locate surrounding context clues. If a pattern match is within 100 characters of an identified `PERSON` or `ORG` entity, the system boosts its confidence score.

### 2. Risk Classification Matrix
Detections are scored via a weighted priority matrix:
* **Critical**: Exposed credentials, API keys, passwords, or documents containing a combination of sensitive identifiers and financial data.
* **High**: Plain-text PII (Aadhaar, Passport, PAN, Driving Licence).
* **Medium**: Department/Ministry names, corporate contact details, or internal files.
* **Low**: Public notice layouts, general reports, or public announcements.

### 3. Retrieval-Augmented Generation (RAG)
For secure Q&A over uploaded files, we build a local vector database:
1. **Document Chunking**: Text is split using paragraph-aware chunking with a size of 512 characters and a 64-character overlap.
2. **Embeddings**: Vector embeddings are generated using the `sentence-transformers/all-MiniLM-L6-v2` model (384 dimensions).
3. **Vector Database**: Chunks are indexed inside **ChromaDB**.
4. **LLM Generation**: Similar chunks are retrieved and sent alongside the user prompt to **Groq (`llama-3.1-8b-instant`)**.
5. **Fail-Safe Response Masking**: A backend filter post-processes the LLM's response. If any raw, unmasked sensitive data value (length $\ge$ 4) from the document is found in the generated answer, the backend instantly overrides it with its masked equivalent.

---

## ⚠️ Challenges Faced & Engineering Solutions

### 1. Eliminating False Positives in Identifier Detection
* **The Problem**: Standard patterns matching bank codes (like SWIFT/BIC) often match uppercase last names (e.g., `UPPARAPALLI` has exactly 11 letters, matching the SWIFT format, triggering false alarms).
* **The Solution**: Implemented a custom validation checker that inspects the country identifier characters of the match. If it does not resolve to a valid ISO 3166-1 alpha-2 country code, the detection is instantly discarded.

### 2. LLM Instruction Drift and PII Leakage
* **The Problem**: Even with strict system prompts, smaller models (like Llama-3.1-8b) occasionally leak raw, unmasked data in conversational Q&A when asked direct questions.
* **The Solution**: Developed a backend post-processing filter that intercepts the LLM's final response, compares it against the document's raw detections list, and automatically redacts any matched strings before serving the response to the user.

### 3. Telemetry Library Version Conflict
* **The Problem**: ChromaDB's telemetry pipeline had a method signature mismatch with the system's updated `posthog` package, triggering noisy console logs during startup.
* **The Solution**: Disabled telemetry at the ChromaDB initialization layer using configuration settings (`Settings(anonymized_telemetry=False)`), improving startup speed and silencing console errors.

### 4. Processing Scanned PDFs and Non-Selectable Image Files
* **The Problem**: A significant number of corporate compliance files are scanned PDF images (e.g. JPGs wrapped inside a PDF envelope) containing no indexable text, causing native text extractors to return empty results.
* **The Solution**: Designed an automated fallback pipeline. When a document yields zero characters during native extraction, the system automatically converts the PDF pages into high-resolution images in-memory and executes Tesseract OCR. Additionally, the code dynamically auto-detects Tesseract binary paths across Windows environment defaults (`C:\Program Files\Tesseract-OCR\tesseract.exe`) and Linux environments, ensuring cross-platform container build portability.

---

## 🚀 Setup Instructions

### Local Setup (Native Python)

#### 1. Clone & Navigate
```bash
git clone https://github.com/rishikroyal/dataguard.git
cd dataguard
```

#### 2. Environment Configuration
Create a virtual environment and install requirements:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

#### 3. Setup Env Variables
Create a `.env` file in the root folder:
```env
GROQ_API_KEY=gsk_your_groq_api_key_here
```

#### 4. Run Server
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Open **`http://localhost:8000`** in your browser.

---

### Docker Deployment (Recommended)

To build and run the application locally using Docker:

```bash
# Build the image
docker build -t dataguard-ai .

# Run the container
docker run -p 8000:8000 -e GROQ_API_KEY=your_key_here dataguard-ai
```

---

## 🔮 Future Improvements

1. **Role-Based Access Control (RBAC)**: Support multiple users, teams, and departments with customizable data access layers.
2. **Multi-language OCR Support**: Integrate advanced cloud vision OCR APIs (e.g., AWS Textract, Google Document AI) to read handwritten and regional language documents.
3. **Native PDF Redaction**: Transition from text-masking output to PDF-native layer removal to support secure PDF downloads.
4. **Persistent Vector Storage**: Swap out in-memory ChromaDB instances for a persistent, centralized vector store (e.g. Qdrant or Pinecone).
5. **Real-time API Scanning**: Expose high-throughput REST webhook endpoints to allow CI/CD pipelines to scan code repositories for secret keys and credentials.

---

<div align="center">
Developed by <strong>Rishik Royal Upparapalli</strong> for the Proteccio Data Innovation Internship Challenge (July 2026)
</div>
