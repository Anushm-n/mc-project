import math
import re
from typing import List, Dict, Tuple, Optional, Callable
from collections import Counter
from .types import FileCategory, SectorInfo

# Known File Signatures & Sub-Markers
MAGIC_SIGNATURES = [
    # Image Standard
    (b"\xFF\xD8\xFF", "image/jpeg", FileCategory.IMAGE, "JPEG Image (Standard Header)", b"\xFF\xD9"),
    (b"\x89PNG\r\n\x1a\n", "image/png", FileCategory.IMAGE, "PNG Image", b"IEND\xaeB`\x82"),
    (b"GIF87a", "image/gif", FileCategory.IMAGE, "GIF Image (87a)", b";"),
    (b"GIF89a", "image/gif", FileCategory.IMAGE, "GIF Image (89a)", b";"),
    (b"BM", "image/bmp", FileCategory.IMAGE, "Bitmap Image", None),
    (b"RIFF", "image/webp_or_audio", FileCategory.IMAGE, "RIFF Container (WEBP/WAV)", None),
    
    # Damaged Image Marker (Header stripped, scanlines / tables survive)
    (b"\xFF\xDB", "image/jpeg", FileCategory.IMAGE, "JPEG Quantization Fragment", b"\xFF\xD9"),
    (b"\xFF\xDA", "image/jpeg", FileCategory.IMAGE, "JPEG Scanline Stream", b"\xFF\xD9"),

    # Documents
    (b"%PDF-", "application/pdf", FileCategory.DOCUMENT, "PDF Document", b"%%EOF"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "application/msword-legacy", FileCategory.DOCUMENT, "Legacy MS Office OLE", None),
    
    # Archives & Modern Office
    (b"PK\x03\x04", "application/zip", FileCategory.ARCHIVE, "ZIP / Office OpenXML", b"PK\x05\x06"),
    (b"\x1F\x8B\x08", "application/gzip", FileCategory.ARCHIVE, "GZIP Archive", None),
    (b"7z\xBC\xAF\x27\x1C", "application/x-7z-compressed", FileCategory.ARCHIVE, "7-Zip Archive", None),
    (b"Rar!\x1A\x07", "application/x-rar", FileCategory.ARCHIVE, "RAR Archive", None),
    
    # Databases
    (b"SQLite format 3\x00", "application/x-sqlite3", FileCategory.DATABASE, "SQLite Database v3", None),
    (b"\x0D\x00", "application/x-sqlite3", FileCategory.DATABASE, "SQLite B-Tree Table Leaf Page", None),
    
    # Executables / Binaries
    (b"MZ", "application/x-dosexec", FileCategory.EXECUTABLE, "Windows Executable/DLL", None),
    (b"\x7FELF", "application/x-elf", FileCategory.EXECUTABLE, "Linux ELF Executable", None),
]

def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of a byte sequence (0.0 to 8.0 bits per byte)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def classify_sector_entropy(entropy: float, is_zero: bool) -> str:
    """Classifies a sector based on its Shannon entropy."""
    if is_zero:
        return "ZERO_PADDING"
    if entropy < 1.0:
        return "SPARSE_REPEATING"
    if entropy < 3.5:
        return "LOW_ENTROPY_DATA"
    if entropy < 5.2:
        return "PLAINTEXT_CODE_STRUCT"
    if entropy < 6.8:
        return "DATABASE_EXECUTABLE"
    return "COMPRESSED_OR_ENCRYPTED"

def detect_text_heuristics(chunk: bytes) -> Tuple[bool, Optional[str], Optional[FileCategory]]:
    """Analyzes byte chunks to detect text, code, JSON, logs, SQL, or tabular data."""
    if not chunk:
        return False, None, None
        
    trimmed = chunk.strip(b"\x00")
    if len(trimmed) < 20:
        return False, None, None

    # Check printable character ratio on trimmed data
    printable_chars = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \t\r\n!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
    printable_count = sum(1 for b in trimmed if b in printable_chars)
    ratio = printable_count / len(trimmed)
    
    if ratio < 0.70:
        return False, None, None
        
    try:
        text = trimmed.decode("utf-8", errors="ignore")
    except Exception:
        text = trimmed.decode("latin-1", errors="ignore")

    # Source code signatures
    code_keywords = ["def ", "import ", "from ", "class ", "function ", "const ", "let ", "var ", "return ", "if (", "public class ", "namespace ", "#include ", "AWS_SECRET", "JWT_"]
    if any(kw in text for kw in code_keywords):
        return True, "text/x-source-code", FileCategory.SOURCE_CODE
        
    # JSON signatures
    stripped = text.strip()
    if (stripped.startswith("{") and "}" in stripped) or (stripped.startswith("[") and "]" in stripped):
        if any(c in stripped for c in [":", "\"", ","]):
            return True, "application/json", FileCategory.STRUCTURED_DATA
            
    # System logs
    log_patterns = [r"\[(?:INFO|ERROR|WARN|DEBUG|CRITICAL)\]", r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", r"GET /|POST /|HTTP/1\.[01]", r"pam_unix", r"sshd:auth"]
    if any(re.search(pat, text) for pat in log_patterns):
        return True, "text/x-log", FileCategory.SYSTEM_LOG

    # SQL signatures
    sql_keywords = ["CREATE TABLE", "INSERT INTO", "SELECT ", "UPDATE ", "DROP TABLE", "PRIMARY KEY", "VALUES ("]
    if any(kw in text.upper() for kw in sql_keywords):
        return True, "application/sql", FileCategory.DATABASE
        
    # Communication (emails / chats)
    if "From:" in text or "To:" in text or "Subject:" in text or re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text):
        # If it also contains legal/contract phrasing
        if any(term in text.upper() for term in ["AGREEMENT", "CONTRACT", "SETTLEMENT", "DISBURSEMENT", "GOVERNING JURISDICTION"]):
            return True, "text/plain", FileCategory.DOCUMENT
        return True, "message/rfc822", FileCategory.COMMUNICATION
        
    # Delimited tabular / CSV
    lines = [l for l in text.split("\n") if l.strip()]
    if len(lines) >= 3:
        comma_counts = [l.count(",") for l in lines[:5]]
        if len(set(comma_counts)) == 1 and comma_counts[0] >= 2:
            return True, "text/csv", FileCategory.STRUCTURED_DATA

    return True, "text/plain", FileCategory.DOCUMENT

class RawSectorScanner:
    """Sliding-window forensic sector scanner for disk dumps and unallocated storage."""
    
    def __init__(self, sector_size: int = 512):
        self.sector_size = sector_size

    def scan_raw_image(
        self,
        raw_data: bytes,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Tuple[List[SectorInfo], List[Dict]]:
        """
        Scans raw storage bytes, builds sector-level entropy map,
        and carves distinct file fragments.
        """
        total_bytes = len(raw_data)
        total_sectors = math.ceil(total_bytes / self.sector_size)
        sector_map: List[SectorInfo] = []
        raw_fragments: List[Dict] = []
        
        current_candidate: Optional[Dict] = None
        
        for s_idx in range(total_sectors):
            offset = s_idx * self.sector_size
            sector_bytes = raw_data[offset:offset + self.sector_size]
            
            is_zero = not any(sector_bytes) or all(b == 0x00 for b in sector_bytes)
            entropy = calculate_entropy(sector_bytes)
            classification = classify_sector_entropy(entropy, is_zero)
            
            sector_info = SectorInfo(
                sector_index=s_idx,
                byte_offset=offset,
                size=len(sector_bytes),
                entropy=entropy,
                classification=classification,
                is_zeroed=is_zero
            )
            sector_map.append(sector_info)
            
            # Check for Magic Signatures at sector start
            matched_magic = None
            for sig, mime, cat, desc, footer in MAGIC_SIGNATURES:
                if sector_bytes.startswith(sig):
                    matched_magic = (sig, mime, cat, desc, footer)
                    break
                    
            if matched_magic:
                if current_candidate:
                    raw_fragments.append(current_candidate)
                    current_candidate = None
                    
                sig, mime, cat, desc, footer = matched_magic
                current_candidate = {
                    "start_sector": s_idx,
                    "end_sector": s_idx,
                    "byte_offset": offset,
                    "byte_length": len(sector_bytes),
                    "detected_type": mime,
                    "category": cat,
                    "description": desc,
                    "expected_footer": footer,
                    "has_valid_header": True,
                    "has_valid_footer": False,
                    "is_text": False
                }
            elif is_zero:
                # Zero sector acts as cluster boundary / delimiter
                if current_candidate:
                    raw_fragments.append(current_candidate)
                    current_candidate = None
            else:
                # Sector is non-zero
                is_txt, mime, cat = detect_text_heuristics(sector_bytes)
                
                if current_candidate:
                    # Check if current candidate matches type
                    if is_txt and current_candidate.get("category") == cat:
                        current_candidate["end_sector"] = s_idx
                        current_candidate["byte_length"] = (offset + len(sector_bytes)) - current_candidate["byte_offset"]
                    elif not is_txt and not current_candidate.get("is_text"):
                        # Continuation of binary candidate
                        current_candidate["end_sector"] = s_idx
                        current_candidate["byte_length"] = (offset + len(sector_bytes)) - current_candidate["byte_offset"]
                        if current_candidate.get("expected_footer") and current_candidate["expected_footer"] in sector_bytes:
                            current_candidate["has_valid_footer"] = True
                            raw_fragments.append(current_candidate)
                            current_candidate = None
                    else:
                        # Transition to new type! Close candidate and start new one
                        raw_fragments.append(current_candidate)
                        current_candidate = {
                            "start_sector": s_idx,
                            "end_sector": s_idx,
                            "byte_offset": offset,
                            "byte_length": len(sector_bytes),
                            "detected_type": mime or "application/octet-stream",
                            "category": cat or (FileCategory.IMAGE if entropy > 6.5 else FileCategory.UNKNOWN),
                            "description": f"Carved {cat.value if cat else 'Binary'}",
                            "expected_footer": None,
                            "has_valid_header": False,
                            "has_valid_footer": False,
                            "is_text": is_txt
                        }
                else:
                    # No active candidate, start new
                    current_candidate = {
                        "start_sector": s_idx,
                        "end_sector": s_idx,
                        "byte_offset": offset,
                        "byte_length": len(sector_bytes),
                        "detected_type": mime or ("image/jpeg" if entropy > 6.5 else "application/octet-stream"),
                        "category": cat or (FileCategory.IMAGE if entropy > 6.5 else FileCategory.UNKNOWN),
                        "description": f"Carved {cat.value if cat else 'Binary'}",
                        "expected_footer": None,
                        "has_valid_header": False,
                        "has_valid_footer": False,
                        "is_text": is_txt
                    }

            if progress_callback and s_idx % 20 == 0:
                progress_callback(min(offset + self.sector_size, total_bytes), total_bytes)

        if current_candidate:
            raw_fragments.append(current_candidate)

        return sector_map, raw_fragments
