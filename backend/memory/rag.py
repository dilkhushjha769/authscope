"""Security Knowledge RAG (Retrieval-Augmented Generation) module.

Provides semantic retrieval of OWASP/CWE/authorization security knowledge using:
  1. ChromaDB + Gemini embeddings  (VECTOR mode — preferred)
  2. NumPy cosine-similarity store + Gemini embeddings  (NUMPY_VECTOR mode — fallback)
  3. Keyword token matching  (KEYWORD mode — always available fallback)

The retrieval mode is reported honestly in every result.  The module NEVER
claims keyword matching is semantic vector retrieval.

Public API:
    SecurityKnowledgeRAG(...)
        .ingest_documents(docs_dir)
        .search(query, category=None, limit=5) -> List[KnowledgeChunk]

Design decisions:
- ChromaDB is optional; import errors are caught and the system degrades gracefully.
- NumPy is optional; if unavailable the system uses keyword search only.
- Gemini embedding API is injected (injectable for unit tests via ``embed_fn``).
- Embedding results are cached in-memory to avoid re-embedding identical text.
- Knowledge documents are chunked on section headers (~300 words each).
- Metadata filtering by category is supported.
- Source attribution is preserved on every chunk.
- Sensitive credential patterns are never embedded or stored.
"""

import hashlib
import math
import re
import uuid
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from backend.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Retrieval mode labels
# ---------------------------------------------------------------------------

class RetrievalMode(str, Enum):
    VECTOR = "vector"               # ChromaDB + Gemini embeddings
    NUMPY_VECTOR = "numpy_vector"   # In-process NumPy cosine similarity + Gemini
    KEYWORD = "keyword_fallback"    # Keyword token matching — NOT semantic retrieval


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class KnowledgeChunk(BaseModel):
    """A retrievable fragment of security knowledge."""

    chunk_id: str = Field(description="Unique chunk identifier")
    source: str = Field(description="Source document file name or URI")
    category: str = Field(default="general", description="Vulnerability category label")
    content: str = Field(description="Raw text content of this chunk")
    retrieval_mode: str = Field(
        default=RetrievalMode.KEYWORD,
        description="How this chunk was retrieved (vector / numpy_vector / keyword_fallback)",
    )
    similarity_score: float = Field(default=0.0, description="Similarity score (0–1)")
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SECRET_RE = re.compile(
    r"(Bearer\s+[A-Za-z0-9\-_.]+\.[A-Za-z0-9\-_.]+\.[A-Za-z0-9\-_.]+"
    r"|eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"
    r"|password\s*[:=]\s*\S+"
    r"|api[_\-]?key\s*[:=]\s*\S+"
    r"|Authorization:\s*\S+)",
    re.IGNORECASE,
)


def _redact(text: str) -> str:
    return _SECRET_RE.sub("[REDACTED]", text)


def _text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _chunk_document(content: str, source: str, category: str, max_words: int = 300) -> List[KnowledgeChunk]:
    """Split *content* into ~max_words-word chunks on section boundaries.

    Sections are detected by Markdown headings (``#`` prefix) or blank lines
    between paragraphs that would create a chunk > max_words.
    """
    # Split on Markdown headings first
    sections = re.split(r"\n(?=#{1,4}\s)", content)
    chunks: List[KnowledgeChunk] = []

    for section in sections:
        section = section.strip()
        if not section:
            continue
        words = section.split()
        if len(words) <= max_words:
            chunks.append(
                KnowledgeChunk(
                    chunk_id=f"chunk_{uuid.uuid4().hex[:8]}",
                    source=source,
                    category=category,
                    content=_redact(section),
                    metadata={"word_count": len(words)},
                )
            )
        else:
            # Further split long sections into max_words paragraphs
            for i in range(0, len(words), max_words):
                sub = " ".join(words[i : i + max_words])
                chunks.append(
                    KnowledgeChunk(
                        chunk_id=f"chunk_{uuid.uuid4().hex[:8]}",
                        source=source,
                        category=category,
                        content=_redact(sub),
                        metadata={"word_count": len(sub.split())},
                    )
                )
    return chunks


def _keyword_score(query: str, text: str) -> float:
    """Return a simple TF-like score for *query* tokens found in *text*."""
    q_tokens = set(re.findall(r"\w+", query.lower()))
    t_tokens = re.findall(r"\w+", text.lower())
    if not q_tokens or not t_tokens:
        return 0.0
    matches = sum(1 for t in t_tokens if t in q_tokens)
    return min(matches / (len(q_tokens) + 1e-9), 1.0)


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    """Pure-Python cosine similarity (fallback when numpy unavailable)."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# Embedding cache
# ---------------------------------------------------------------------------

class EmbeddingCache:
    """In-memory LRU-style cache for text embeddings, keyed by SHA-256 hash."""

    def __init__(self, max_size: int = 512) -> None:
        self._cache: Dict[str, List[float]] = {}
        self._max_size = max_size

    def get(self, text: str) -> Optional[List[float]]:
        return self._cache.get(_text_hash(text))

    def put(self, text: str, embedding: List[float]) -> None:
        if len(self._cache) >= self._max_size:
            # Evict oldest (first) entry
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
        self._cache[_text_hash(text)] = embedding

    def __len__(self) -> int:
        return len(self._cache)


# ---------------------------------------------------------------------------
# Vector store backends
# ---------------------------------------------------------------------------

class _NumpyVectorStore:
    """Pure-Python/NumPy in-process vector store (no external service needed)."""

    def __init__(self) -> None:
        self._chunks: List[KnowledgeChunk] = []
        self._embeddings: List[List[float]] = []

    def add(self, chunk: KnowledgeChunk, embedding: List[float]) -> None:
        self._chunks.append(chunk)
        self._embeddings.append(embedding)

    def search(
        self,
        query_embedding: List[float],
        category: Optional[str],
        limit: int,
    ) -> List[Tuple[KnowledgeChunk, float]]:
        """Return top-*limit* chunks by cosine similarity."""
        scored: List[Tuple[KnowledgeChunk, float]] = []
        for chunk, emb in zip(self._chunks, self._embeddings):
            if category and chunk.category.lower() != category.lower():
                continue
            score = _cosine_similarity(query_embedding, emb)
            scored.append((chunk, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:limit]

    def __len__(self) -> int:
        return len(self._chunks)


class _ChromaVectorStore:
    """ChromaDB-backed vector store (optional dependency)."""

    def __init__(self, persist_dir: str, collection_name: str = "authscope_knowledge") -> None:
        import chromadb  # type: ignore[import]

        self._client = chromadb.PersistentClient(path=persist_dir)
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info("ChromaDB collection ready", extra={"collection": collection_name})

    def add(self, chunk: KnowledgeChunk, embedding: List[float]) -> None:
        self._collection.upsert(
            ids=[chunk.chunk_id],
            embeddings=[embedding],
            documents=[chunk.content],
            metadatas=[
                {
                    "source": chunk.source,
                    "category": chunk.category,
                    **{k: str(v) for k, v in chunk.metadata.items()},
                }
            ],
        )

    def search(
        self,
        query_embedding: List[float],
        category: Optional[str],
        limit: int,
    ) -> List[Tuple[KnowledgeChunk, float]]:
        where: Optional[Dict[str, Any]] = {"category": category} if category else None
        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=limit,
            where=where,
            include=["documents", "metadatas", "distances"],
        )
        chunks: List[Tuple[KnowledgeChunk, float]] = []
        for doc, meta, dist in zip(
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        ):
            score = 1.0 - float(dist)  # cosine space: distance -> similarity
            chunks.append(
                (
                    KnowledgeChunk(
                        chunk_id=meta.get("chunk_id", ""),
                        source=meta.get("source", ""),
                        category=meta.get("category", "general"),
                        content=doc,
                        metadata={k: v for k, v in meta.items() if k not in ("source", "category")},
                    ),
                    score,
                )
            )
        return chunks

    def __len__(self) -> int:
        return self._collection.count()


# ---------------------------------------------------------------------------
# Gemini embedding helper
# ---------------------------------------------------------------------------

def _make_gemini_embed_fn(api_key: Optional[str] = None) -> Callable[[str], List[float]]:
    """Return a Gemini embedding function using the google-genai SDK."""

    def _embed(text: str) -> List[float]:
        try:
            from google import genai  # type: ignore[import]
            from google.genai import types as genai_types  # type: ignore[import]

            client_kwargs: Dict[str, Any] = {}
            if api_key:
                client_kwargs["api_key"] = api_key

            client = genai.Client(**client_kwargs)
            response = client.models.embed_content(
                model="models/text-embedding-004",
                contents=text,
            )
            # Response structure: EmbedContentResponse.embeddings[0].values
            embedding_obj = response.embeddings[0] if response.embeddings else None
            if embedding_obj is None:
                raise ValueError("Empty embedding response from Gemini API")
            return list(embedding_obj.values)
        except Exception as exc:
            logger.warning(
                "Gemini embedding failed — returning zero vector",
                extra={"error": str(exc)},
            )
            return []

    return _embed


# ---------------------------------------------------------------------------
# Main RAG class
# ---------------------------------------------------------------------------


class SecurityKnowledgeRAG:
    """Semantic security knowledge retrieval with keyword fallback.

    Usage::

        rag = SecurityKnowledgeRAG(
            chroma_path="data/chroma_kb",
            gemini_api_key="...",
            use_vector=True,
        )
        rag.ingest_documents(Path("knowledge_base/"))
        chunks = rag.search("BOLA basket endpoint", category="BOLA_IDOR", limit=3)

    For unit tests, inject a deterministic embedding function::

        rag = SecurityKnowledgeRAG(use_vector=True, embed_fn=lambda t: [0.1]*768)

    The ``retrieval_mode`` field on every returned ``KnowledgeChunk`` honestly
    reflects how it was retrieved.
    """

    def __init__(
        self,
        chroma_path: Optional[str] = None,
        gemini_api_key: Optional[str] = None,
        use_vector: bool = True,
        embed_fn: Optional[Callable[[str], List[float]]] = None,
        collection_name: str = "authscope_knowledge",
    ) -> None:
        self._cache = EmbeddingCache()
        self._keyword_chunks: List[KnowledgeChunk] = []  # always populated for fallback
        self._vector_store: Optional[Any] = None
        self._mode = RetrievalMode.KEYWORD

        # Resolve embedding function
        self._embed_fn: Optional[Callable[[str], List[float]]] = embed_fn
        if embed_fn is None and use_vector:
            self._embed_fn = _make_gemini_embed_fn(gemini_api_key)

        if use_vector:
            self._mode = self._init_vector_backend(chroma_path, collection_name)

    def _init_vector_backend(
        self, chroma_path: Optional[str], collection_name: str
    ) -> RetrievalMode:
        """Try ChromaDB first, then NumPy vector store, then keyword."""
        # 1. Try ChromaDB
        if chroma_path:
            try:
                self._vector_store = _ChromaVectorStore(
                    persist_dir=chroma_path, collection_name=collection_name
                )
                logger.info("SecurityKnowledgeRAG: using ChromaDB vector backend")
                return RetrievalMode.VECTOR
            except ImportError:
                logger.info("SecurityKnowledgeRAG: chromadb not available, falling back to NumPy")
            except Exception as exc:
                logger.warning(
                    "SecurityKnowledgeRAG: ChromaDB init failed, falling back to NumPy",
                    extra={"error": str(exc)},
                )

        # 2. Try NumPy cosine-similarity store
        try:
            import numpy  # noqa: F401 — just test availability
            self._vector_store = _NumpyVectorStore()
            logger.info("SecurityKnowledgeRAG: using NumPy in-process vector backend")
            return RetrievalMode.NUMPY_VECTOR
        except ImportError:
            logger.info("SecurityKnowledgeRAG: numpy not available, using keyword fallback only")

        # 3. Keyword fallback
        self._vector_store = None
        return RetrievalMode.KEYWORD

    # ------------------------------------------------------------------
    # Document ingestion
    # ------------------------------------------------------------------

    def ingest_documents(self, docs_dir: Path) -> int:
        """Chunk, embed (if vector mode), and index all ``*.md`` files in *docs_dir*.

        Returns the number of chunks indexed.
        """
        if not docs_dir.exists():
            logger.warning(
                "SecurityKnowledgeRAG: knowledge_base dir not found",
                extra={"path": str(docs_dir)},
            )
            return 0

        total = 0
        for md_file in sorted(docs_dir.glob("*.md")):
            try:
                content = md_file.read_text(encoding="utf-8")
                category = _infer_category_from_filename(md_file.name)
                chunks = _chunk_document(content, source=md_file.name, category=category)
                for chunk in chunks:
                    self._index_chunk(chunk)
                    total += 1
                logger.debug(
                    "SecurityKnowledgeRAG: ingested document",
                    extra={"file": md_file.name, "chunks": len(chunks)},
                )
            except Exception as exc:
                logger.error(
                    "SecurityKnowledgeRAG: failed to ingest document",
                    extra={"file": md_file.name, "error": str(exc)},
                )
        logger.info(
            "SecurityKnowledgeRAG: ingestion complete",
            extra={"total_chunks": total, "mode": self._mode},
        )
        return total

    def add_chunk(self, chunk: KnowledgeChunk) -> None:
        """Manually add a single chunk (for programmatic knowledge injection)."""
        self._index_chunk(chunk)

    def _index_chunk(self, chunk: KnowledgeChunk) -> None:
        """Add *chunk* to keyword store and (if available) vector store."""
        self._keyword_chunks.append(chunk)

        if self._vector_store is not None and self._embed_fn is not None:
            embedding = self._get_or_compute_embedding(chunk.content)
            if embedding:
                self._vector_store.add(chunk, embedding)

    def _get_or_compute_embedding(self, text: str) -> List[float]:
        """Return cached embedding or compute a fresh one."""
        cached = self._cache.get(text)
        if cached is not None:
            return cached
        if self._embed_fn is None:
            return []
        embedding = self._embed_fn(text)
        if embedding:
            self._cache.put(text, embedding)
        return embedding

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 5,
    ) -> List[KnowledgeChunk]:
        """Retrieve the top-*limit* knowledge chunks relevant to *query*.

        Tries vector search first; falls back to keyword search if unavailable.
        The ``retrieval_mode`` field on each result honestly labels the method used.
        """
        if (
            self._mode in (RetrievalMode.VECTOR, RetrievalMode.NUMPY_VECTOR)
            and self._vector_store is not None
            and self._embed_fn is not None
        ):
            try:
                return self._vector_search(query, category, limit)
            except Exception as exc:
                logger.warning(
                    "SecurityKnowledgeRAG: vector search failed — using keyword fallback",
                    extra={"error": str(exc)},
                )

        return self._keyword_search(query, category, limit)

    def _vector_search(
        self, query: str, category: Optional[str], limit: int
    ) -> List[KnowledgeChunk]:
        """Embed *query* and retrieve top chunks by cosine similarity."""
        query_embedding = self._get_or_compute_embedding(query)
        if not query_embedding:
            logger.warning("SecurityKnowledgeRAG: empty query embedding — falling back to keyword")
            return self._keyword_search(query, category, limit)

        results = self._vector_store.search(query_embedding, category, limit)  # type: ignore[union-attr]
        mode_label = (
            RetrievalMode.VECTOR
            if isinstance(self._vector_store, _ChromaVectorStore)
            else RetrievalMode.NUMPY_VECTOR
        )
        return [
            chunk.model_copy(update={"retrieval_mode": mode_label, "similarity_score": score})
            for chunk, score in results
        ]

    def _keyword_search(
        self, query: str, category: Optional[str], limit: int
    ) -> List[KnowledgeChunk]:
        """Keyword token scoring — clearly labelled as NOT semantic retrieval.

        This is an honest fallback; results are returned with
        ``retrieval_mode = "keyword_fallback"``.
        """
        candidates = self._keyword_chunks
        if category:
            candidates = [c for c in candidates if c.category.lower() == category.lower()]

        scored = [
            (chunk, _keyword_score(query, chunk.content))
            for chunk in candidates
        ]
        scored.sort(key=lambda x: x[1], reverse=True)
        top = scored[:limit]
        return [
            chunk.model_copy(
                update={
                    "retrieval_mode": RetrievalMode.KEYWORD,
                    "similarity_score": score,
                }
            )
            for chunk, score in top
            if score > 0.0
        ]

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def retrieval_mode(self) -> RetrievalMode:
        """The active retrieval mode (VECTOR / NUMPY_VECTOR / KEYWORD)."""
        return self._mode

    @property
    def chunk_count(self) -> int:
        """Total number of indexed keyword chunks."""
        return len(self._keyword_chunks)

    @property
    def embedding_cache_size(self) -> int:
        """Number of cached embeddings."""
        return len(self._cache)


# ---------------------------------------------------------------------------
# Helper: infer category from filename
# ---------------------------------------------------------------------------

_CATEGORY_MAP: Dict[str, str] = {
    "bola": "BOLA_IDOR",
    "idor": "BOLA_IDOR",
    "bfla": "BFLA",
    "privilege": "PRIVILEGE_ESCALATION",
    "escalation": "PRIVILEGE_ESCALATION",
    "mass_assignment": "MASS_ASSIGNMENT",
    "mass-assignment": "MASS_ASSIGNMENT",
    "auth": "MISSING_AUTH",
    "authentication": "MISSING_AUTH",
    "multi_step": "MULTI_STEP_CHAIN",
    "owasp": "general",
    "secure_coding": "secure_coding",
    "remediation": "remediation",
    "authscope": "authscope",
}


def _infer_category_from_filename(filename: str) -> str:
    name_lower = filename.lower().replace("-", "_").replace(".md", "")
    for key, cat in _CATEGORY_MAP.items():
        if key in name_lower:
            return cat
    return "general"

