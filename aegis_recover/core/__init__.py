"""
AegisRecover AI: Next-Generation AI-Assisted Data Recovery & Digital Forensics System.
"""
from .types import (
    FileCategory, PriorityLevel, IntegrityStatus,
    RecoveredFragment, SectorInfo, RelationshipEdge, ScanReport
)
from .engine import RecoveryEngine
from .simulator import CorruptedStorageSimulator

__all__ = [
    "RecoveryEngine",
    "CorruptedStorageSimulator",
    "FileCategory",
    "PriorityLevel",
    "IntegrityStatus",
    "RecoveredFragment",
    "SectorInfo",
    "RelationshipEdge",
    "ScanReport"
]
