#!/usr/bin/env python3
"""
scripts/ingest_threat_intel.py — Load threat intel documents into ChromaDB.

Reads all .txt files from data/threat_intel/, splits them into chunks,
and upserts them into the ChromaDB vector store with OpenAI embeddings.

Usage:
    python scripts/ingest_threat_intel.py
    python scripts/ingest_threat_intel.py --force   # re-ingest even if populated
"""

from __future__ import annotations
import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import THREAT_INTEL_DIR, CHUNK_SIZE, CHUNK_OVERLAP
from agent.retriever import get_retriever


def chunk_text(text: str, chunk_size: int = CHUNK_SIZE,
               overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Split text into overlapping chunks for embedding."""
    chunks = []
    start  = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end].strip())
        start += chunk_size - overlap
    return [c for c in chunks if len(c) > 50]  # drop tiny chunks


def ingest_file(retriever, file_path: Path) -> int:
    """Ingest a single threat intel file into ChromaDB. Returns chunk count."""
    text   = file_path.read_text(encoding="utf-8")
    chunks = chunk_text(text)
    source = file_path.name

    docs      = []
    metadatas = []
    ids       = []

    for i, chunk in enumerate(chunks):
        chunk_id = hashlib.md5(f"{source}:{i}:{chunk[:50]}".encode()).hexdigest()
        docs.append(chunk)
        metadatas.append({"source": source, "chunk_index": i})
        ids.append(chunk_id)

    retriever.add_documents(docs, metadatas, ids)
    return len(chunks)


def main():
    parser = argparse.ArgumentParser(description="Ingest threat intel into ChromaDB")
    parser.add_argument("--force", action="store_true",
                        help="Re-ingest even if DB is already populated")
    args = parser.parse_args()

    retriever = get_retriever()
    existing  = retriever.count()

    if existing > 0 and not args.force:
        print(f"[OK] ChromaDB already contains {existing} documents. "
              f"Use --force to re-ingest.")
        return

    intel_dir = Path(THREAT_INTEL_DIR)
    if not intel_dir.exists():
        print(f"❌ Threat intel directory not found: {intel_dir}")
        sys.exit(1)

    files = list(intel_dir.glob("*.txt"))
    if not files:
        print(f"❌ No .txt files found in {intel_dir}")
        sys.exit(1)

    print(f"[*] Found {len(files)} threat intel files")
    total_chunks = 0

    for file_path in sorted(files):
        print(f"   Ingesting: {file_path.name} ... ", end="", flush=True)
        count = ingest_file(retriever, file_path)
        total_chunks += count
        print(f"{count} chunks")

    print(f"\n[OK] Ingestion complete: {total_chunks} chunks -> ChromaDB")
    print(f"   Collection '{retriever._collection.name}' now has "
          f"{retriever.count()} documents.")


if __name__ == "__main__":
    main()
