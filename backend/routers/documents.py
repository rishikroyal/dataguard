"""
GET /api/documents                — list all stored documents
GET /api/documents/{doc_id}       — full document detail
"""

from fastapi import APIRouter, HTTPException
import backend.store as store

router = APIRouter()


@router.get("/documents")
def list_documents():
    return {"documents": store.all_summaries()}


@router.get("/documents/{doc_id}")
def get_document(doc_id: str):
    doc = store.get(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # Return everything except raw text (large) and api_key (sensitive)
    return {k: v for k, v in doc.items() if k not in ("text", "api_key")}
