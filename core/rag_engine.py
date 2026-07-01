"""
RAG Engine
Retrieval-Augmented Generation using ChromaDB + sentence-transformers.
Enables accurate, context-aware Q&A over uploaded documents.
"""

import os
import logging
import hashlib
from typing import List, Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class RAGEngine:
    """
    Lightweight RAG pipeline using ChromaDB for vector storage
    and sentence-transformers for embeddings.
    Designed to work in-memory for demos, with optional persistence.
    """

    CHUNK_SIZE = 512         # Characters per chunk
    CHUNK_OVERLAP = 64       # Overlap between chunks
    TOP_K = 5                # Number of results to retrieve

    def __init__(self, persist_dir: Optional[str] = None):
        self.persist_dir = persist_dir or os.getenv("CHROMA_PERSIST_DIR", "./chroma_db")
        self._client = None
        self._collection = None
        self._embedder = None
        self.is_available = False
        self._initialize()

    def _initialize(self):
        """Initialize ChromaDB client and embedding model."""
        try:
            import chromadb
            from chromadb.config import Settings

            # Use in-memory for simplicity; persistent optionally
            self._client = chromadb.Client()
            self.is_available = True
            logger.info("ChromaDB initialized (in-memory mode).")
        except ImportError:
            logger.warning("ChromaDB not available. RAG features disabled.")
            self.is_available = False
            return

        try:
            from sentence_transformers import SentenceTransformer
            self._embedder = SentenceTransformer("all-MiniLM-L6-v2")
            logger.info("Sentence transformer loaded: all-MiniLM-L6-v2")
        except ImportError:
            logger.warning("sentence-transformers not available. Using ChromaDB default embeddings.")
            self._embedder = None

    def _get_or_create_collection(self, doc_id: str):
        """Get or create a ChromaDB collection for a document."""
        collection_name = f"doc_{doc_id[:32]}"
        try:
            return self._client.get_collection(collection_name)
        except Exception:
            return self._client.create_collection(
                name=collection_name,
                metadata={"hnsw:space": "cosine"},
            )

    def index_document(self, text: str, filename: str) -> str:
        """
        Chunk and index a document into ChromaDB.
        Returns the document ID for later retrieval.
        """
        if not self.is_available:
            return ""

        # Generate stable doc ID from content hash
        doc_id = hashlib.md5(text.encode()).hexdigest()

        try:
            collection = self._get_or_create_collection(doc_id)

            # Check if already indexed
            existing = collection.count()
            if existing > 0:
                logger.info(f"Document {filename} already indexed with {existing} chunks.")
                return doc_id

            # Create chunks
            chunks = self._chunk_text(text)

            if not chunks:
                return doc_id

            # Generate embeddings or use ChromaDB defaults
            if self._embedder:
                embeddings = self._embedder.encode(chunks).tolist()
                collection.add(
                    documents=chunks,
                    embeddings=embeddings,
                    ids=[f"{doc_id}_{i}" for i in range(len(chunks))],
                    metadatas=[{"source": filename, "chunk_idx": i} for i in range(len(chunks))],
                )
            else:
                collection.add(
                    documents=chunks,
                    ids=[f"{doc_id}_{i}" for i in range(len(chunks))],
                    metadatas=[{"source": filename, "chunk_idx": i} for i in range(len(chunks))],
                )

            logger.info(f"Indexed {len(chunks)} chunks from {filename}.")
            return doc_id

        except Exception as e:
            logger.error(f"Indexing failed: {e}")
            return ""

    def retrieve(self, query: str, doc_id: str, top_k: int = None) -> List[str]:
        """
        Retrieve relevant document chunks for a query.
        Returns list of text chunks sorted by relevance.
        """
        if not self.is_available or not doc_id:
            return []

        top_k = top_k or self.TOP_K

        try:
            collection = self._get_or_create_collection(doc_id)

            if collection.count() == 0:
                return []

            if self._embedder:
                query_embedding = self._embedder.encode([query]).tolist()
                results = collection.query(
                    query_embeddings=query_embedding,
                    n_results=min(top_k, collection.count()),
                )
            else:
                results = collection.query(
                    query_texts=[query],
                    n_results=min(top_k, collection.count()),
                )

            documents = results.get("documents", [[]])[0]
            return documents

        except Exception as e:
            logger.error(f"Retrieval failed: {e}")
            return []

    def _chunk_text(self, text: str) -> List[str]:
        """
        Split text into overlapping chunks for better retrieval coverage.
        Uses sentence-aware splitting where possible.
        """
        chunks = []
        text = text.strip()

        if len(text) <= self.CHUNK_SIZE:
            return [text] if text else []

        # Try to split by paragraphs first
        paragraphs = [p.strip() for p in text.split('\n\n') if p.strip()]

        current_chunk = ""
        for para in paragraphs:
            if len(current_chunk) + len(para) <= self.CHUNK_SIZE:
                current_chunk += " " + para if current_chunk else para
            else:
                if current_chunk:
                    chunks.append(current_chunk.strip())
                # Handle long paragraphs
                if len(para) > self.CHUNK_SIZE:
                    # Split by sentences
                    sentences = para.replace('. ', '.|').replace('! ', '!|').replace('? ', '?|').split('|')
                    sub_chunk = ""
                    for sent in sentences:
                        if len(sub_chunk) + len(sent) <= self.CHUNK_SIZE:
                            sub_chunk += " " + sent if sub_chunk else sent
                        else:
                            if sub_chunk:
                                chunks.append(sub_chunk.strip())
                            sub_chunk = sent
                    if sub_chunk:
                        current_chunk = sub_chunk
                    else:
                        current_chunk = ""
                else:
                    current_chunk = para

        if current_chunk:
            chunks.append(current_chunk.strip())

        # Add overlap between chunks
        if len(chunks) > 1:
            overlapped = []
            for i, chunk in enumerate(chunks):
                if i > 0:
                    prev_words = chunks[i-1].split()
                    overlap_text = " ".join(prev_words[-20:])  # Last 20 words
                    chunk = overlap_text + " " + chunk
                overlapped.append(chunk)
            return overlapped

        return chunks

    def clear_index(self, doc_id: str):
        """Remove a document's index from ChromaDB."""
        if not self.is_available:
            return
        try:
            collection_name = f"doc_{doc_id[:32]}"
            self._client.delete_collection(collection_name)
            logger.info(f"Cleared index for document {doc_id}")
        except Exception as e:
            logger.warning(f"Could not clear index: {e}")

    def get_stats(self, doc_id: str) -> Dict[str, Any]:
        """Get indexing statistics for a document."""
        if not self.is_available or not doc_id:
            return {"indexed": False, "chunks": 0}

        try:
            collection = self._get_or_create_collection(doc_id)
            return {"indexed": True, "chunks": collection.count()}
        except Exception:
            return {"indexed": False, "chunks": 0}
