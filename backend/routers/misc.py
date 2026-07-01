"""
GET /api/audit        — recent audit events
GET /api/health       — health check
POST /api/sample/{name} — load a sample document
"""

import io
import os
from pathlib import Path
from datetime import datetime
from functools import lru_cache

from fastapi import APIRouter, HTTPException, BackgroundTasks

import backend.store as store
from core.audit_logger import AuditLogger
from core.document_processor import DocumentProcessor
from core.detection_engine import DetectionEngine
from core.risk_classifier import RiskClassifier
from core.rag_engine import RAGEngine

router = APIRouter()

SAMPLE_FILES = {
    "sensitive": "sample_docs/sample_sensitive.txt",
    "hr_csv":    "sample_docs/sample_hr_data.csv",
}


@lru_cache(maxsize=1)
def _audit():
    return AuditLogger()


@router.get("/health")
def health():
    return {
        "status":    "ok",
        "timestamp": datetime.now().isoformat(),
        "version":   "1.0.0",
    }


@router.get("/audit")
def get_audit(limit: int = 200):
    events = _audit().get_recent_events(limit=limit)
    stats  = _audit().get_stats()
    return {"events": events, "stats": stats}


@router.post("/sample/{name}")
def load_sample(name: str):
    if name not in SAMPLE_FILES:
        raise HTTPException(404, f"Unknown sample: {name}. Valid: {list(SAMPLE_FILES)}")

    path = Path(SAMPLE_FILES[name])
    if not path.exists():
        raise HTTPException(404, "Sample file not found on server")

    content  = path.read_bytes()
    filename = path.name

    processor    = DocumentProcessor(ocr_enabled=False)
    detector     = DetectionEngine(use_spacy=True)
    classifier   = RiskClassifier()
    rag_engine   = RAGEngine()

    doc_result = processor.process(io.BytesIO(content), filename)
    if not doc_result["success"]:
        raise HTTPException(422, doc_result.get("error", "Processing failed"))

    text         = doc_result["text"]
    detections   = detector.detect(text)
    risk_profile = classifier.classify(detections, len(text))
    det_dicts    = [d.to_dict() for d in detections]

    try:
        rag_doc_id = rag_engine.index_document(text, filename)
    except Exception:
        rag_doc_id = ""

    doc_data = {
        "filename":        filename,
        "format":          doc_result.get("format", "txt"),
        "pages":           doc_result.get("pages", 1),
        "word_count":      doc_result.get("word_count", len(text.split())),
        "file_size":       len(content),
        "text":            text,
        "processed_at":    datetime.now().strftime("%Y-%m-%d %H:%M"),
        "detections":      det_dicts,
        "risk_profile":    risk_profile.to_dict(),
        "risk_level":      risk_profile.overall_risk,
        "risk_score":      risk_profile.risk_score,
        "detection_count": len(detections),
        "rag_doc_id":      rag_doc_id,
        "api_key":         "",
    }

    doc_id = store.create(doc_data)
    _audit().log("SCAN_COMPLETE", "api-session",
                 filename=filename, risk_level=risk_profile.overall_risk,
                 detection_count=len(detections))

    return {
        "doc_id":             doc_id,
        "filename":           filename,
        "format":             doc_data["format"],
        "pages":              doc_data["pages"],
        "word_count":         doc_data["word_count"],
        "file_size":          doc_data["file_size"],
        "processed_at":       doc_data["processed_at"],
        "detection_count":    len(detections),
        "risk_level":         risk_profile.overall_risk,
        "risk_score":         risk_profile.risk_score,
        "document_clearance": risk_profile.document_clearance,
        "detections":         det_dicts,
        "risk_profile":       risk_profile.to_dict(),
    }
