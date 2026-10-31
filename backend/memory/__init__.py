"""AuthScope Memory Subsystem.

Provides three memory capabilities for the AI security assessment engine:
1. Short-term assessment memory  — isolated per-assessment in-process context.
2. Long-term assessment memory   — persisted metadata via existing SQLite/FindingRepository.
3. Semantic security knowledge RAG — ChromaDB + Gemini embeddings with keyword fallback.

Public entry point: MemoryManager (manager.py).
"""

from backend.memory.manager import MemoryManager

__all__ = ["MemoryManager"]

