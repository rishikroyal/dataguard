"""
Sensitive Data Detection & Compliance Assistant
Core Package
"""

from .document_processor import DocumentProcessor
from .detection_engine import DetectionEngine
from .risk_classifier import RiskClassifier
from .ai_engine import AIEngine
from .rag_engine import RAGEngine
from .redactor import Redactor
from .audit_logger import AuditLogger

__version__ = "1.0.0"
__author__ = "Sensitive Data Detection System"

__all__ = [
    "DocumentProcessor",
    "DetectionEngine",
    "RiskClassifier",
    "AIEngine",
    "RAGEngine",
    "Redactor",
    "AuditLogger",
]
