"""
POST /api/qa
Body: { doc_id, question, api_key? }
"""

import logging
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException

import backend.store as store
from core.ai_engine import AIEngine
from core.rag_engine import RAGEngine
from core.audit_logger import AuditLogger
from functools import lru_cache

logger = logging.getLogger(__name__)
router = APIRouter()


class QARequest(BaseModel):
    doc_id:   str
    question: str
    api_key:  str = ""


@lru_cache(maxsize=1)
def _rag():
    return RAGEngine()

@lru_cache(maxsize=1)
def _audit():
    return AuditLogger()


@router.post("/qa")
def answer_question(req: QARequest):
    doc = store.get(req.doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")

    api_key = req.api_key or doc.get("api_key", "")
    ai      = AIEngine(api_key=api_key)
    rag     = _rag()

    # RAG retrieval
    rag_doc_id = doc.get("rag_doc_id", "")
    chunks     = []
    if rag_doc_id:
        try:
            chunks = rag.retrieve(req.question, rag_doc_id, top_k=3)
        except Exception as e:
            logger.warning("RAG retrieve failed: %s", e)

    # Re-hydrate detections and risk_profile for the AI call
    from core.detection_engine import Detection, SensitiveDataType
    from core.risk_classifier import RiskProfile

    answer = ai.answer_question(
        question=req.question,
        document_text=doc["text"],
        detections=[],          # Pass raw list — ai_engine has fallback
        risk_profile=None,
        filename=doc["filename"],
        context_chunks=chunks,
        raw_risk_profile=doc.get("risk_profile"),
        raw_detections=doc.get("detections"),
    )

    _audit().log("QA_QUERY", "api-session",
                 filename=doc["filename"],
                 user_action=req.question[:200],
                 details={"ai_powered": ai.is_available, "chunks": len(chunks)})

    return {"answer": answer, "ai_powered": ai.is_available}
