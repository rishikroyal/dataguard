"""
In-memory document store.
Maps doc_id (UUID) → document data dict.
"""

import uuid
from typing import Dict, Any, Optional

# {doc_id: {...}} — lives for the lifetime of the server process
_docs: Dict[str, Dict[str, Any]] = {}


def create(data: dict) -> str:
    doc_id = str(uuid.uuid4())
    _docs[doc_id] = data
    return doc_id


def get(doc_id: str) -> Optional[dict]:
    return _docs.get(doc_id)


def all_summaries() -> list[dict]:
    """Return lightweight summary rows (no full text or embeddings)."""
    return [
        {
            "doc_id":          k,
            "filename":        v["filename"],
            "format":          v.get("format", "unknown"),
            "risk_level":      v["risk_level"],
            "risk_score":      v["risk_score"],
            "detection_count": v["detection_count"],
            "word_count":      v.get("word_count", 0),
            "file_size":       v.get("file_size", 0),
            "processed_at":    v["processed_at"],
        }
        for k, v in _docs.items()
    ]


def exists(doc_id: str) -> bool:
    return doc_id in _docs
