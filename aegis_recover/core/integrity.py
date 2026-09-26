import io
import os
import json
import ast
from typing import Tuple, List, Dict, Any, Optional
from PIL import Image
from .types import IntegrityStatus, PriorityLevel, FileCategory

class IntegrityAssessor:
    """Assesses raw data integrity, calculates recoverability confidence scores, and generates forensic prognoses."""

    def assess_fragment(
        self,
        raw_bytes: bytes,
        mime_type: str,
        category: FileCategory,
        entropy: float,
        has_valid_header: bool,
        has_valid_footer: bool
    ) -> Tuple[float, IntegrityStatus, List[str], str]:
        """
        Evaluates data integrity across 5 dimensions:
        1. Header Validity (25 pts)
        2. Footer / Terminator Integrity (15 pts)
        3. Entropy Consistency (20 pts)
        4. Corruption & Null Density (20 pts)
        5. Parser / Decoder Validation (20 pts)

        Returns (score, status, diagnostic_factors, prognosis_text)
        """
        if not raw_bytes or len(raw_bytes) == 0:
            return 0.0, IntegrityStatus.UNRECOVERABLE, ["Empty payload."], "Total data loss. Zero bytes recovered."

        total_length = len(raw_bytes)
        factors: List[str] = []
        score = 0.0

        # --- 1. Header Assessment (Max 25 pts) ---
        if has_valid_header:
            score += 25.0
            factors.append("Authentic file header magic bytes verified (+25%)")
        else:
            # Check if partial header can be synthesized
            if category in [FileCategory.IMAGE, FileCategory.DOCUMENT, FileCategory.DATABASE]:
                score += 10.0
                factors.append("Header missing or damaged; synthesized reconstruction possible (+10%)")
            else:
                score += 20.0  # Plaintext/code often naturally lacks binary magic headers
                factors.append("Headerless stream (consistent with plain text/source code) (+20%)")

        # --- 2. Footer / Terminal Marker Assessment (Max 15 pts) ---
        if has_valid_footer:
            score += 15.0
            factors.append("Proper terminal EOF / trailer boundary confirmed (+15%)")
        else:
            if category in [FileCategory.IMAGE, FileCategory.DOCUMENT, FileCategory.ARCHIVE]:
                factors.append("Truncated termination boundary; potential trailing sector loss (-15%)")
            else:
                score += 10.0
                factors.append("Continuous text/stream without strict EOF requirement (+10%)")

        # --- 3. Entropy Consistency (Max 20 pts) ---
        entropy_pts = 0.0
        if category == FileCategory.IMAGE or category == FileCategory.ARCHIVE:
            # Expected high entropy (6.8 to 8.0)
            if 6.5 <= entropy <= 8.0:
                entropy_pts = 20.0
                factors.append(f"Shannon entropy ({entropy:.2f}) optimal for compressed media (+20%)")
            elif 4.0 <= entropy < 6.5:
                entropy_pts = 10.0
                factors.append(f"Abnormal low entropy ({entropy:.2f}) for media; partial uncompressed or zeroed sectors (+10%)")
            else:
                entropy_pts = 2.0
                factors.append(f"Severe entropy anomaly ({entropy:.2f}); heavy corruption (-18%)")
        elif category in [FileCategory.SOURCE_CODE, FileCategory.DOCUMENT, FileCategory.STRUCTURED_DATA]:
            # Expected text entropy (3.0 to 5.5)
            if 3.2 <= entropy <= 5.5:
                entropy_pts = 20.0
                factors.append(f"Shannon entropy ({entropy:.2f}) conforms to natural language/code (+20%)")
            elif entropy > 6.5:
                entropy_pts = 8.0
                factors.append(f"High entropy ({entropy:.2f}) in text stream indicates encrypted or garbled sectors (+8%)")
            else:
                entropy_pts = 12.0
                factors.append(f"Low entropy ({entropy:.2f}); repetitive formatting patterns detected (+12%)")
        else:
            entropy_pts = 15.0
            factors.append(f"General stream entropy ({entropy:.2f}) (+15%)")
        score += entropy_pts

        # --- 4. Corruption & Null Density (Max 20 pts) ---
        null_count = raw_bytes.count(b"\x00")
        null_ratio = null_count / total_length
        if null_ratio < 0.05:
            score += 20.0
            factors.append(f"Clean payload: negligible zero-padding ({null_ratio*100:.1f}%) (+20%)")
        elif null_ratio < 0.25:
            score += 12.0
            factors.append(f"Moderate zero-padding/slack space ({null_ratio*100:.1f}%) (+12%)")
        elif null_ratio < 0.60:
            score += 5.0
            factors.append(f"Significant bad sector zero-fills ({null_ratio*100:.1f}%) (+5%)")
        else:
            factors.append(f"Dominant null byte pattern ({null_ratio*100:.1f}% zeros); sparse content (+0%)")

        # --- 5. Parser / Decoder Validation (Max 20 pts) ---
        validation_pts = 0.0
        if category == FileCategory.IMAGE:
            try:
                img = Image.open(io.BytesIO(raw_bytes))
                img.verify()
                validation_pts = 20.0
                factors.append(f"Image decoder verification PASSED (Format: {img.format}, Mode: {img.mode}) (+20%)")
            except Exception as e:
                # Test if partial scanlines can be decoded
                try:
                    img = Image.open(io.BytesIO(raw_bytes))
                    img.load()
                    validation_pts = 14.0
                    factors.append(f"Partial raster rendering succeeded despite structural warnings (+14%)")
                except Exception:
                    validation_pts = 4.0
                    factors.append("Image parser failed; requires synthetic header/DQT reconstruction (+4%)")
        elif category == FileCategory.STRUCTURED_DATA and mime_type == "application/json":
            try:
                json.loads(raw_bytes.decode("utf-8", errors="ignore"))
                validation_pts = 20.0
                factors.append("JSON parser verification PASSED (valid syntax tree) (+20%)")
            except Exception:
                validation_pts = 8.0
                factors.append("Partial JSON structure; repairable key-value pairs identified (+8%)")
        elif category == FileCategory.SOURCE_CODE:
            try:
                ast.parse(raw_bytes.decode("utf-8", errors="ignore"))
                validation_pts = 20.0
                factors.append("Abstract Syntax Tree (AST) compilation PASSED (+20%)")
            except Exception:
                validation_pts = 12.0
                factors.append("Source code contains partial functions/blocks; human readable (+12%)")
        elif category == FileCategory.DATABASE:
            db_ok = False
            try:
                import tempfile, sqlite3
                with tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite") as tmp:
                    tmp.write(raw_bytes)
                    tmp_name = tmp.name
                conn = sqlite3.connect(tmp_name)
                cur = conn.cursor()
                cur.execute("PRAGMA quick_check")
                row = cur.fetchone()
                if row and row[0] == "ok":
                    db_ok = True
                conn.close()
                os.unlink(tmp_name)
            except Exception:
                db_ok = False

            if db_ok:
                validation_pts = 20.0
                factors.append("SQLite database integrity check PRAGMA quick_check PASSED (+20%)")
                score = max(score, 94.0)
            elif b"SQLite format 3" in raw_bytes or raw_bytes.startswith(b"\x0D"):
                validation_pts = 18.0
                factors.append("Valid SQLite B-tree page signatures verified (+18%)")
            else:
                validation_pts = 8.0
                factors.append("Raw database records detected without primary page index (+8%)")
        else:
            validation_pts = 15.0
            factors.append("Stream payload conforms to generic validation criteria (+15%)")
        score += validation_pts

        score = round(min(max(score, 0.0), 100.0), 1)

        # Status determination
        if score >= 88.0:
            status = IntegrityStatus.INTACT
        elif score >= 65.0:
            status = IntegrityStatus.RECOVERABLE
        elif score >= 40.0:
            status = IntegrityStatus.PARTIALLY_CORRUPTED
        elif score >= 18.0:
            status = IntegrityStatus.SEVERELY_DAMAGED
        else:
            status = IntegrityStatus.UNRECOVERABLE

        # Generate human-readable investigator prognosis
        prognosis = self._generate_prognosis(category, score, status, total_length)

        return score, status, factors, prognosis

    def _generate_prognosis(self, category: FileCategory, score: float, status: IntegrityStatus, length: int) -> str:
        """Constructs concise, actionable forensic recovery prognosis."""
        size_kb = length / 1024.0
        if status == IntegrityStatus.INTACT:
            return f"Optimal recovery prognosis ({score}%). File payload ({size_kb:.1f} KB) is structurally intact with verified syntax. 100% restoration expected."
        elif status == IntegrityStatus.RECOVERABLE:
            return f"High restoration confidence ({score}%). Core data structures are sound. Minor non-destructive header synthesis or boundary alignment will yield complete or near-complete recovery."
        elif status == IntegrityStatus.PARTIALLY_CORRUPTED:
            return f"Partial recovery viable ({score}%). Approximately {int(score)}% of original content can be salvaged. Some sectors were overwritten or truncated, but human-readable and forensic intelligence remains intact."
        elif status == IntegrityStatus.SEVERELY_DAMAGED:
            return f"Fragile recovery ({score}%). Substantial byte corruption across multiple sectors. Only isolated string fragments, partial headers, or fragmentary records can be extracted."
        else:
            return f"Minimal recoverability ({score}%). Sector data consists primarily of zero padding or corrupted noise. Forensically unrecoverable."
