"""Convert provider audit logs into the normalized investigation schema.

Adapters are deterministic and configuration-driven. Each normalized record
keeps the original provider event under ``source_event`` so the provenance
graph's raw leaves still contain exactly what the provider emitted.
"""
from .base import AdapterConfig, SUPPORTED_FORMATS, convert, convert_to_jsonl, load_config

__all__ = ['AdapterConfig', 'SUPPORTED_FORMATS', 'convert', 'convert_to_jsonl', 'load_config']
