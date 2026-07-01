"""
POST /api/upload
Accepts a document file, runs the full analysis pipeline, stores results,
and returns a complete response that the frontend can cache.
"""

import io
import os
import logging
from datetime import datetime
from functools import lru_cache

from fastapi import APIRouter, UploadFile, File, Form, HTTPException

import backend.store as store
from core.document_processor import DocumentProcessor
from core.detection_engine import DetectionEngine
from core.risk_classifier import RiskClassifier
from core.rag_engine import RAGEngine
from core.audit_logger import AuditLogger

logger = logging.getLogger(__name__)
router = APIRouter()

# Singletons — created once on first request
@lru_cache(maxsize=1)
def _detector():
    return DetectionEngine(use_spacy=True)

@lru_cache(maxsize=1)
def _classifier():
    return RiskClassifier()

@lru_cache(maxsize=1)
def _rag():
    return RAGEngine()

@lru_cache(maxsize=1)
def _audit():
    return AuditLogger()


@router.post("/upload")
async def upload_document(
    file: UploadFile = File(...),
    api_key: str = Form(default=""),
    use_ocr: bool = Form(default=False),
):
    filename = file.filename or "document"
    content  = await file.read()

    # ── Extract text ──────────────────────────────────────────────
    processor = DocumentProcessor(ocr_enabled=use_ocr)
    doc_result = processor.process(io.BytesIO(content), filename)

    if not doc_result["success"]:
        raise HTTPException(status_code=422,
                            detail=doc_result.get("error", "Text extraction failed"))

    text = doc_result["text"]
    if not text.strip():
        raise HTTPException(status_code=422,
                            detail="No readable text found in this file.")

    # ── Detect → classify ─────────────────────────────────────────
    detections   = _detector().detect(text)
    risk_profile = _classifier().classify(detections, len(text))
    det_dicts    = [d.to_dict() for d in detections]

    # ── RAG index ─────────────────────────────────────────────────
    try:
        rag_doc_id = _rag().index_document(text, filename)
    except Exception as e:
        logger.warning("RAG indexing failed: %s", e)
        rag_doc_id = ""

    # ── Store ─────────────────────────────────────────────────────
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
        "api_key":         api_key,            # forwarded on QA/report calls
    }

    doc_id = store.create(doc_data)

    _audit().log(
        "SCAN_COMPLETE", "api-session",
        filename=filename,
        risk_level=risk_profile.overall_risk,
        detection_count=len(detections),
    )

    return {
        "doc_id":              doc_id,
        "filename":            filename,
        "format":              doc_data["format"],
        "pages":               doc_data["pages"],
        "word_count":          doc_data["word_count"],
        "file_size":           doc_data["file_size"],
        "processed_at":        doc_data["processed_at"],
        "detection_count":     len(detections),
        "risk_level":          risk_profile.overall_risk,
        "risk_score":          risk_profile.risk_score,
        "document_clearance":  risk_profile.document_clearance,
        "detections":          det_dicts,
        "risk_profile":        risk_profile.to_dict(),
    }
