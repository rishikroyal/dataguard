"""
POST /api/report       — generate AI compliance report
POST /api/redact       — return redacted document text
"""

from pydantic import BaseModel
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

import backend.store as store
from core.ai_engine import AIEngine
from core.redactor import Redactor
from core.audit_logger import AuditLogger
from functools import lru_cache

router = APIRouter()

class ReportRequest(BaseModel):
    doc_id:  str
    api_key: str = ""

class RedactRequest(BaseModel):
    doc_id: str
    mode:   str = "partial"   # full | partial | hash

@lru_cache(maxsize=1)
def _audit():
    return AuditLogger()


@router.post("/report")
def generate_report(req: ReportRequest):
    doc = store.get(req.doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")

    api_key = req.api_key or doc.get("api_key", "")
    ai      = AIEngine(api_key=api_key)

    # Re-build lightweight risk profile representation for the AI call
    summary = ai.generate_compliance_summary(
        document_text=doc["text"],
        detections=[],
        risk_profile=None,
        filename=doc["filename"],
        raw_risk_profile=doc.get("risk_profile"),
        raw_detections=doc.get("detections"),
    )

    _audit().log("REPORT_GENERATED", "api-session",
                 filename=doc["filename"],
                 risk_level=doc.get("risk_level"),
                 detection_count=doc.get("detection_count", 0),
                 details={"ai_powered": ai.is_available})

    return {"report": summary, "ai_powered": ai.is_available}


@router.post("/redact")
def redact_document(req: RedactRequest):
    doc = store.get(req.doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")

    valid_modes = ("full", "partial", "hash")
    mode        = req.mode if req.mode in valid_modes else "partial"

    r = Redactor(mode=mode)
    redacted_text, count = r.redact(doc["text"], [])   # pass raw dicts

    _audit().log("REDACTION_APPLIED", "api-session",
                 filename=doc["filename"], detection_count=count)

    return {
        "redacted":  redacted_text,
        "count":     count,
        "filename":  doc["filename"],
    }


class PDFReportRequest(BaseModel):
    doc_id:  str
    summary: str


@router.post("/report/pdf")
def download_pdf_report(req: PDFReportRequest):
    from fastapi.responses import Response
    from utils.helpers import generate_pdf_report

    doc = store.get(req.doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")

    pdf_bytes = generate_pdf_report(
        filename=doc["filename"],
        detections=doc.get("detections", []),
        risk_profile=doc.get("risk_profile", {}),
        summary=req.summary,
    )

    if not pdf_bytes:
        raise HTTPException(500, "Could not generate PDF report")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={doc['filename']}_report.pdf"}
    )

