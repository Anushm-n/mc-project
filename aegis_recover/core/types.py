from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
import uuid

class FileCategory(str, Enum):
    IMAGE = "IMAGE"
    DOCUMENT = "DOCUMENT"
    DATABASE = "DATABASE"
    ARCHIVE = "ARCHIVE"
    SOURCE_CODE = "SOURCE_CODE"
    STRUCTURED_DATA = "STRUCTURED_DATA"
    COMMUNICATION = "COMMUNICATION"
    SYSTEM_LOG = "SYSTEM_LOG"
    EXECUTABLE = "EXECUTABLE"
    UNKNOWN = "UNKNOWN"

class PriorityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    TRIVIAL = "TRIVIAL"

class IntegrityStatus(str, Enum):
    INTACT = "INTACT"
    RECOVERABLE = "RECOVERABLE"
    PARTIALLY_CORRUPTED = "PARTIALLY_CORRUPTED"
    SEVERELY_DAMAGED = "SEVERELY_DAMAGED"
    UNRECOVERABLE = "UNRECOVERABLE"

class ExtractedEntity(BaseModel):
    entity_type: str
    value: str
    confidence: float = 1.0

class SectorInfo(BaseModel):
    sector_index: int
    byte_offset: int
    size: int
    entropy: float
    classification: str
    is_zeroed: bool
    fragment_id: Optional[str] = None

class RecoveredFragment(BaseModel):
    fragment_id: str = Field(default_factory=lambda: f"FRAG_{uuid.uuid4().hex[:8].upper()}")
    start_sector: int
    end_sector: int
    byte_offset: int
    byte_length: int
    detected_type: str
    category: FileCategory
    entropy: float
    recoverability_score: float = 0.0  # 0.0 - 100.0%
    integrity_status: IntegrityStatus = IntegrityStatus.PARTIALLY_CORRUPTED
    priority: PriorityLevel = PriorityLevel.MEDIUM
    entities: List[ExtractedEntity] = []
    summary: str = ""
    suggested_filename: str = "recovered_fragment.bin"
    has_valid_header: bool = False
    has_valid_footer: bool = False
    reconstruction_notes: List[str] = []
    preview_data: Optional[str] = None  # Text snippet, base64 image, or table representation
    raw_hex_preview: Optional[str] = None
    linked_fragment_ids: List[str] = []
    reconstructed_bytes: Optional[bytes] = None
    gemini_verification: Optional[Dict[str, Any]] = None

    class Config:
        arbitrary_types_allowed = True

class RelationshipEdge(BaseModel):
    source_id: str
    target_id: str
    relationship_type: str  # "CONTINUATION", "STRUCTURAL_PARENT", "SHARED_ENTITY", "TEMPORAL_COOCCURRENCE", "SCHEMA_DATA"
    confidence: float
    explanation: str

class ScanProgress(BaseModel):
    scan_id: str
    status: str
    processed_bytes: int
    total_bytes: int
    percent_complete: float
    fragments_found: int

class ScanReport(BaseModel):
    scan_id: str
    source_name: str
    timestamp: str
    total_bytes: int
    total_sectors: int
    sector_size: int
    fragments: List[RecoveredFragment]
    relationships: List[RelationshipEdge]
    stats: Dict[str, Any]
    sector_map_summary: List[SectorInfo]
    saved_folder: Optional[str] = None
    gemini_report: Optional[Dict[str, Any]] = None
