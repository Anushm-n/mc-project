import base64
import datetime
import uuid
from typing import List, Dict, Any, Optional, Tuple

from .types import (
    RecoveredFragment, SectorInfo, RelationshipEdge, ScanReport,
    FileCategory, PriorityLevel, IntegrityStatus
)
from .scanner import RawSectorScanner, calculate_entropy
from .classifier import SemanticClassifier
from .reconstructor import FragmentReconstructor
from .integrity import IntegrityAssessor
from .graph_engine import FragmentGraphEngine

def format_hex_preview(data: bytes, max_bytes: int = 128) -> str:
    """Generates standard forensic hex dump with ASCII sidebar."""
    lines = []
    chunk = data[:max_bytes]
    for i in range(0, len(chunk), 16):
        line_bytes = chunk[i:i + 16]
        hex_str = " ".join(f"{b:02X}" for b in line_bytes)
        hex_str = f"{hex_str:<48}"
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in line_bytes)
        lines.append(f"{i:04X}  {hex_str}  |{ascii_str}|")
    if len(data) > max_bytes:
        lines.append(f"... ({len(data) - max_bytes} additional bytes omitted)")
    return "\n".join(lines)

class RecoveryEngine:
    """Master AI-Assisted Data Recovery and Digital Forensics Orchestrator."""

    def __init__(self, sector_size: int = 512):
        self.sector_size = sector_size
        self.scanner = RawSectorScanner(sector_size=sector_size)
        self.classifier = SemanticClassifier()
        self.reconstructor = FragmentReconstructor()
        self.assessor = IntegrityAssessor()
        self.graph_engine = FragmentGraphEngine()

    def process_raw_storage(
        self,
        raw_data: bytes,
        source_name: str = "raw_disk_image.dd",
        progress_callback=None
    ) -> ScanReport:
        """
        Executes end-to-end recovery pipeline:
        1. Sector-level carving & Shannon entropy mapping
        2. Multi-modal AI classification & entity extraction
        3. Automated structural reconstruction & header synthesis
        4. Data integrity assessment & recoverability scoring
        5. Graph relationship modeling & cluster linking
        """
        scan_id = f"SCAN_{uuid.uuid4().hex[:8].upper()}"
        total_bytes = len(raw_data)
        total_sectors = (total_bytes + self.sector_size - 1) // self.sector_size

        # 1. Sliding-window Sector Scan
        sector_map, raw_candidates = self.scanner.scan_raw_image(
            raw_data, progress_callback=progress_callback
        )

        recovered_fragments: List[RecoveredFragment] = []

        # 2. Process each carved fragment candidate
        for idx, cand in enumerate(raw_candidates):
            frag_bytes = raw_data[cand["byte_offset"] : cand["byte_offset"] + cand["byte_length"]]
            if not frag_bytes or all(b == 0 for b in frag_bytes):
                continue

            frag_entropy = calculate_entropy(frag_bytes)
            cat: FileCategory = cand["category"]
            mime: str = cand["detected_type"]

            # AI Semantic Classification
            sem_result = self.classifier.analyze_fragment(frag_bytes, mime, cat)

            # Automated Header & Structure Reconstruction
            reconstructed_bytes = frag_bytes
            reconstruction_notes = []
            records_preview = None

            if cat == FileCategory.IMAGE and mime == "image/jpeg":
                reconstructed_bytes, rnotes = self.reconstructor.repair_jpeg(frag_bytes)
                reconstruction_notes.extend(rnotes)
            elif cat == FileCategory.IMAGE and mime == "image/png":
                reconstructed_bytes, rnotes = self.reconstructor.repair_png(frag_bytes)
                reconstruction_notes.extend(rnotes)
            elif cat == FileCategory.DOCUMENT and mime == "application/pdf":
                reconstructed_bytes, rnotes = self.reconstructor.repair_pdf(frag_bytes)
                reconstruction_notes.extend(rnotes)
            elif cat == FileCategory.DATABASE and "sqlite" in mime:
                reconstructed_bytes, rnotes, records = self.reconstructor.repair_sqlite(frag_bytes)
                reconstruction_notes.extend(rnotes)
                if records:
                    records_preview = records
            elif sem_result["is_textual"]:
                reconstructed_bytes, rnotes = self.reconstructor.repair_text(frag_bytes)
                reconstruction_notes.extend(rnotes)

            # Integrity Assessment & Recoverability Score
            score, status, diag_factors, prognosis = self.assessor.assess_fragment(
                raw_bytes=reconstructed_bytes,
                mime_type=mime,
                category=cat,
                entropy=frag_entropy,
                has_valid_header=cand.get("has_valid_header", False),
                has_valid_footer=cand.get("has_valid_footer", False)
            )

            # Determine Suggested Filename & Extension
            ext_map = {
                "image/jpeg": ".jpg",
                "image/png": ".png",
                "application/pdf": ".pdf",
                "application/x-sqlite3": ".sqlite",
                "text/x-source-code": ".py",
                "application/json": ".json",
                "text/csv": ".csv",
                "text/x-log": ".log",
                "message/rfc822": ".eml",
                "text/plain": ".txt"
            }
            ext = ext_map.get(mime, ".bin")
            filename = f"recovered_sector_{cand['start_sector']:04d}_{cat.value.lower()}{ext}"

            # Create visual or textual preview
            preview_str = None
            if cat == FileCategory.IMAGE:
                # Provide base64 data URI if previewable
                try:
                    preview_str = f"data:{mime};base64,{base64.b64encode(reconstructed_bytes).decode('ascii')}"
                except Exception:
                    preview_str = None
            elif records_preview:
                preview_str = "\n".join(f"[Record {r['cell_index']}] " + " | ".join(r['extracted_fields']) for r in records_preview)
            elif sem_result["is_textual"]:
                preview_str = sem_result.get("text_sample")

            fragment_obj = RecoveredFragment(
                fragment_id=f"FRAG_{cand['start_sector']:04d}_{uuid.uuid4().hex[:4].upper()}",
                start_sector=cand["start_sector"],
                end_sector=cand["end_sector"],
                byte_offset=cand["byte_offset"],
                byte_length=cand["byte_length"],
                detected_type=mime,
                category=cat,
                entropy=frag_entropy,
                recoverability_score=score,
                integrity_status=status,
                priority=sem_result["priority"],
                entities=sem_result["entities"],
                summary=sem_result["summary"],
                suggested_filename=filename,
                has_valid_header=cand.get("has_valid_header", False),
                has_valid_footer=cand.get("has_valid_footer", False),
                reconstruction_notes=reconstruction_notes + [f"Prognosis: {prognosis}"] + diag_factors,
                preview_data=preview_str,
                raw_hex_preview=format_hex_preview(frag_bytes, max_bytes=128),
                reconstructed_bytes=reconstructed_bytes
            )
            recovered_fragments.append(fragment_obj)

        # 3. Graph Engine: Discover Relationships & Continuations
        relationships = self.graph_engine.build_relationship_graph(recovered_fragments)

        # 4. Statistical Summary
        category_counts = {}
        priority_counts = {}
        for f in recovered_fragments:
            category_counts[f.category.value] = category_counts.get(f.category.value, 0) + 1
            priority_counts[f.priority.value] = priority_counts.get(f.priority.value, 0) + 1

        avg_recoverability = round(
            sum(f.recoverability_score for f in recovered_fragments) / len(recovered_fragments), 1
        ) if recovered_fragments else 0.0

        stats = {
            "total_fragments": len(recovered_fragments),
            "critical_intel_count": priority_counts.get(PriorityLevel.CRITICAL.value, 0),
            "average_recoverability_pct": avg_recoverability,
            "category_distribution": category_counts,
            "priority_distribution": priority_counts,
            "active_relationships": len(relationships)
        }

        # Sector map summary (downsampled for lightweight transfer if large)
        sector_summary = sector_map if len(sector_map) <= 256 else sector_map[::max(1, len(sector_map)//256)]

        return ScanReport(
            scan_id=scan_id,
            source_name=source_name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            total_bytes=total_bytes,
            total_sectors=total_sectors,
            sector_size=self.sector_size,
            fragments=recovered_fragments,
            relationships=relationships,
            stats=stats,
            sector_map_summary=sector_summary
        )
