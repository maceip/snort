"""Sealed Parquet segments (plan section 4.1)."""

from snort.store.seal import SEALED_MANIFEST, seal_segments, verify_sealed_chain

__all__ = ["SEALED_MANIFEST", "seal_segments", "verify_sealed_chain"]
