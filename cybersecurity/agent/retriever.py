"""
agent/retriever.py — ChromaDB RAG pipeline for threat intelligence.

Provides a singleton ThreatIntelRetriever that wraps a persistent
ChromaDB collection with OpenAI embeddings.

Usage:
    from agent.retriever import get_retriever
    retriever = get_retriever()
    results = retriever.query("Tor exit node suspicious login", k=5)
"""

from __future__ import annotations
import chromadb
from chromadb.utils import embedding_functions

from config import (
    CHROMA_DIR, CHROMA_COLLECTION, OPENAI_API_KEY,
    EMBEDDING_MODEL, TOP_K_RETRIEVAL,
)

_retriever: "ThreatIntelRetriever | None" = None


class ThreatIntelRetriever:
    """Thin wrapper around a ChromaDB collection with OpenAI embeddings."""

    def __init__(self) -> None:
        self._client = chromadb.PersistentClient(path=str(CHROMA_DIR))
        ef = embedding_functions.OpenAIEmbeddingFunction(
            api_key=OPENAI_API_KEY,
            model_name=EMBEDDING_MODEL,
        )
        self._collection = self._client.get_or_create_collection(
            name=CHROMA_COLLECTION,
            embedding_function=ef,
        )

    def add_documents(self, docs: list[str], metadatas: list[dict], ids: list[str]) -> None:
        """Upsert documents into the collection."""
        self._collection.upsert(documents=docs, metadatas=metadatas, ids=ids)

    def query(self, query: str, k: int = TOP_K_RETRIEVAL) -> list[dict]:
        """
        Semantic search over threat intel documents.
        Returns list of {text, source, distance} dicts.
        """
        count = self._collection.count()
        if count == 0:
            return []

        n_results = min(k, count)
        results   = self._collection.query(
            query_texts=[query],
            n_results=n_results,
        )

        output = []
        for i, doc in enumerate(results["documents"][0]):
            output.append({
                "text":     doc,
                "source":   results["metadatas"][0][i].get("source", "unknown"),
                "distance": round(results["distances"][0][i], 4)
                            if results.get("distances") else None,
            })
        return output

    def count(self) -> int:
        return self._collection.count()


def get_retriever() -> ThreatIntelRetriever:
    """Return the singleton retriever, creating it on first call."""
    global _retriever
    if _retriever is None:
        _retriever = ThreatIntelRetriever()
    return _retriever
