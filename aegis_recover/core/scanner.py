import math
import os
import re
import struct
from typing import List, Dict, Tuple, Optional, Callable
from collections import Counter
from .types import FileCategory, SectorInfo

# Known File Signatures & Sub-Markers (Forensic Carving Signatures)
MAGIC_SIGNATURES = [
    # Image Standard
    (b"\xFF\xD8\xFF", "image/jpeg", FileCategory.IMAGE, "JPEG Image", b"\xFF\xD9"),
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
    
    # Executables / Binaries
    (b"MZ", "application/x-dosexec", FileCategory.EXECUTABLE, "Windows Executable/DLL", None),
    (b"\x7FELF", "application/x-elf", FileCategory.EXECUTABLE, "Linux ELF Executable", None),
]

# File Extension Hints for Dedicated User File Uploads
EXTENSION_HINTS = {
    ".jpg": ("image/jpeg", FileCategory.IMAGE, "JPEG Image", b"\xFF\xD9"),
    ".jpeg": ("image/jpeg", FileCategory.IMAGE, "JPEG Image", b"\xFF\xD9"),
    ".png": ("image/png", FileCategory.IMAGE, "PNG Image", b"IEND\xaeB`\x82"),
    ".gif": ("image/gif", FileCategory.IMAGE, "GIF Image", b";"),
    ".bmp": ("image/bmp", FileCategory.IMAGE, "Bitmap Image", None),
    ".webp": ("image/webp", FileCategory.IMAGE, "WebP Image", None),
    ".pdf": ("application/pdf", FileCategory.DOCUMENT, "PDF Document", b"%%EOF"),
    ".doc": ("application/msword-legacy", FileCategory.DOCUMENT, "Legacy MS Word Document", None),
    ".docx": ("application/zip", FileCategory.DOCUMENT, "Word Document (DOCX)", b"PK\x05\x06"),
    ".xls": ("application/vnd.ms-excel", FileCategory.STRUCTURED_DATA, "Excel Spreadsheet", None),
    ".xlsx": ("application/zip", FileCategory.STRUCTURED_DATA, "Excel Spreadsheet (XLSX)", b"PK\x05\x06"),
    ".sqlite": ("application/x-sqlite3", FileCategory.DATABASE, "SQLite Database", None),
    ".db": ("application/x-sqlite3", FileCategory.DATABASE, "Database File", None),
    ".sql": ("application/sql", FileCategory.DATABASE, "SQL Database Dump", None),
    ".py": ("text/x-source-code", FileCategory.SOURCE_CODE, "Python Source Script", None),
    ".c": ("text/x-source-code", FileCategory.SOURCE_CODE, "C Source Code", None),
    ".cpp": ("text/x-source-code", FileCategory.SOURCE_CODE, "C++ Source Code", None),
    ".h": ("text/x-source-code", FileCategory.SOURCE_CODE, "C/C++ Header File", None),
    ".java": ("text/x-source-code", FileCategory.SOURCE_CODE, "Java Source Code", None),
    ".go": ("text/x-source-code", FileCategory.SOURCE_CODE, "Go Source Code", None),
    ".rs": ("text/x-source-code", FileCategory.SOURCE_CODE, "Rust Source Code", None),
    ".ts": ("text/x-source-code", FileCategory.SOURCE_CODE, "TypeScript Source Code", None),
    ".sh": ("text/x-source-code", FileCategory.SOURCE_CODE, "Shell Script", None),
    ".js": ("text/x-source-code", FileCategory.SOURCE_CODE, "JavaScript File", None),
    ".html": ("text/html", FileCategory.SOURCE_CODE, "HTML Document", None),
    ".css": ("text/css", FileCategory.SOURCE_CODE, "CSS Stylesheet", None),
    ".json": ("application/json", FileCategory.STRUCTURED_DATA, "JSON Data Structure", None),
    ".csv": ("text/csv", FileCategory.STRUCTURED_DATA, "CSV Spreadsheet Data", None),
    ".tsv": ("text/csv", FileCategory.STRUCTURED_DATA, "TSV Tabular Data", None),
    ".xml": ("application/xml", FileCategory.STRUCTURED_DATA, "XML Document", None),
    ".txt": ("text/plain", FileCategory.DOCUMENT, "Plain Text Document", None),
    ".md": ("text/markdown", FileCategory.DOCUMENT, "Markdown Document", None),
    ".log": ("text/x-log", FileCategory.SYSTEM_LOG, "System Log File", None),
    ".eml": ("message/rfc822", FileCategory.COMMUNICATION, "Email Message (RFC822)", None),
    ".zip": ("application/zip", FileCategory.ARCHIVE, "ZIP Archive", b"PK\x05\x06"),
    ".gz": ("application/gzip", FileCategory.ARCHIVE, "GZIP Compressed Archive", None),
    ".7z": ("application/x-7z-compressed", FileCategory.ARCHIVE, "7-Zip Archive", None),
    ".rar": ("application/x-rar", FileCategory.ARCHIVE, "RAR Archive", None),
}

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
    if len(trimmed) < 10:
        return False, None, None

    printable_chars = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \t\r\n!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
    printable_count = sum(1 for b in trimmed if b in printable_chars)
    ratio = printable_count / len(trimmed)
    
    if ratio < 0.60:
        return False, None, None
        
    try:
        text = trimmed.decode("utf-8", errors="ignore")
    except Exception:
        text = trimmed.decode("latin-1", errors="ignore")

    # Source code signatures
    code_keywords = ["def ", "import ", "from ", "class ", "function ", "const ", "let ", "var ", "return ", "if (", "public class ", "namespace ", "#include ", "AWS_SECRET", "JWT_", "SELECT ", "INSERT "]
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
        if any(term in text.upper() for term in ["AGREEMENT", "CONTRACT", "SETTLEMENT", "DISBURSEMENT", "GOVERNING JURISDICTION"]):
            return True, "text/plain", FileCategory.DOCUMENT
        return True, "message/rfc822", FileCategory.COMMUNICATION
        
    # Delimited tabular / CSV
    lines = [l for l in text.split("\n") if l.strip()]
    if len(lines) >= 2:
        comma_counts = [l.count(",") for l in lines[:5]]
        if len(set(comma_counts)) == 1 and comma_counts[0] >= 1:
            return True, "text/csv", FileCategory.STRUCTURED_DATA

    return True, "text/plain", FileCategory.DOCUMENT

class RawSectorScanner:
    """Forensic sector scanner & file carver for disk images and uploaded corrupted files."""
    
    def __init__(self, sector_size: int = 512):
        self.sector_size = sector_size

    def scan_raw_image(
        self,
        raw_data: bytes,
        source_name: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Tuple[List[SectorInfo], List[Dict]]:
        """
        Scans storage bytes, builds sector-level entropy map,
        and carves distinct file fragments.
        """
        total_bytes = len(raw_data)
        if total_bytes == 0:
            return [], []

        total_sectors = math.ceil(total_bytes / self.sector_size)
        sector_map: List[SectorInfo] = []
        raw_fragments: List[Dict] = []
        
        # 1. Build Sector Map across entire file
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

            if progress_callback and s_idx % 20 == 0:
                progress_callback(min(offset + self.sector_size, total_bytes), total_bytes)

        # 2. Check if this is a Dedicated Single File Upload vs Raw Disk Dump Image
        ext = os.path.splitext(source_name or "")[1].lower()
        is_disk_dump = (
            ext in [".dd", ".raw", ".img", ".bin", ".dump", ".vmdk", ".iso"]
            or (source_name and source_name.lower().startswith("simulated_"))
            or (source_name is None)
        )

        # CASE A: Dedicated Uploaded File (e.g. photo.jpg, notes.txt, resume.pdf, database.sqlite)
        if not is_disk_dump and total_bytes > 0:
            # Determine format from extension hint or internal signatures
            hint_mime, hint_cat, hint_desc, hint_footer = EXTENSION_HINTS.get(
                ext, ("application/octet-stream", FileCategory.UNKNOWN, "Uploaded File", None)
            )

            # Check if magic signature exists anywhere in file
            found_magic = None
            for sig, mime, cat, desc, footer in MAGIC_SIGNATURES:
                if sig in raw_data[:2048]:
                    found_magic = (sig, mime, cat, desc, footer)
                    break

            is_txt, txt_mime, txt_cat = detect_text_heuristics(raw_data[:2048])
            overall_entropy = calculate_entropy(raw_data)

            if found_magic:
                sig, mime, cat, desc, footer = found_magic
                has_hdr = raw_data.startswith(sig)
                has_ftr = (footer in raw_data) if footer else True
            elif hint_cat != FileCategory.UNKNOWN:
                mime, cat, desc, footer = hint_mime, hint_cat, hint_desc, hint_footer
                has_hdr = True if (cat in [FileCategory.SOURCE_CODE, FileCategory.STRUCTURED_DATA, FileCategory.DOCUMENT] and (is_txt or total_bytes > 0)) else False
                has_ftr = (footer in raw_data) if footer else True
            elif is_txt and txt_cat:
                mime, cat, desc, footer = txt_mime or "text/plain", txt_cat, "Text Document", None
                has_hdr = True
                has_ftr = True
            else:
                cat = FileCategory.IMAGE if overall_entropy > 6.5 else (FileCategory.DOCUMENT if overall_entropy > 3.0 else FileCategory.UNKNOWN)
                mime = "image/jpeg" if overall_entropy > 6.5 else "application/octet-stream"
                desc = f"Salvaged File ({cat.value})"
                footer = None
                has_hdr = False
                has_ftr = False

            base_name = os.path.basename(source_name) if source_name else "uploaded_file"
            custom_name = f"salvaged_{base_name}" if not base_name.lower().startswith("salvaged_") else base_name

            raw_fragments.append({
                "start_sector": 0,
                "end_sector": total_sectors - 1,
                "byte_offset": 0,
                "byte_length": total_bytes,
                "detected_type": mime,
                "category": cat,
                "description": desc,
                "expected_footer": footer,
                "has_valid_header": has_hdr,
                "has_valid_footer": has_ftr,
                "is_text": (cat in [FileCategory.DOCUMENT, FileCategory.SOURCE_CODE, FileCategory.COMMUNICATION, FileCategory.SYSTEM_LOG] or is_txt),
                "custom_filename": custom_name
            })
            return sector_map, raw_fragments

        # CASE B: Raw Storage Disk Dump Carving (sliding sector scanning)
        current_candidate: Optional[Dict] = None

        for s_idx in range(total_sectors):
            offset = s_idx * self.sector_size
            sector_bytes = raw_data[offset:offset + self.sector_size]
            is_zero = not any(sector_bytes) or all(b == 0x00 for b in sector_bytes)
            entropy = sector_map[s_idx].entropy

            # Check for magic signatures (at start or within first 64 bytes)
            matched_magic = None
            for sig, mime, cat, desc, footer in MAGIC_SIGNATURES:
                sig_pos = sector_bytes.find(sig)
                if sig_pos != -1 and sig_pos <= 64:
                    matched_magic = (sig, mime, cat, desc, footer, sig_pos)
                    break

            if matched_magic:
                if current_candidate:
                    raw_fragments.append(current_candidate)
                    current_candidate = None

                sig, mime, cat, desc, footer, sig_pos = matched_magic
                
                # Check for explicit SQLite v3 database size from 100-byte header
                expected_total_len = None
                if sig == b"SQLite format 3\x00" and len(sector_bytes) >= sig_pos + 32:
                    try:
                        p_size = struct.unpack(">H", sector_bytes[sig_pos + 16 : sig_pos + 18])[0]
                        p_count = struct.unpack(">I", sector_bytes[sig_pos + 28 : sig_pos + 32])[0]
                        if p_size in [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536] and 0 < p_count < 100000:
                            expected_total_len = p_size * p_count
                    except Exception:
                        pass

                current_candidate = {
                    "start_sector": s_idx,
                    "end_sector": s_idx,
                    "byte_offset": offset + sig_pos,
                    "byte_length": len(sector_bytes) - sig_pos,
                    "detected_type": mime,
                    "category": cat,
                    "description": desc,
                    "expected_footer": footer,
                    "expected_total_len": expected_total_len,
                    "has_valid_header": sig_pos == 0,
                    "has_valid_footer": False,
                    "is_text": False
                }
                if expected_total_len and current_candidate["byte_length"] >= expected_total_len:
                    current_candidate["byte_length"] = expected_total_len
                    current_candidate["has_valid_footer"] = True
                    raw_fragments.append(current_candidate)
                    current_candidate = None
            elif is_zero:
                if current_candidate:
                    if current_candidate.get("expected_total_len") and current_candidate["byte_length"] < current_candidate["expected_total_len"]:
                        # Continue accumulating database sectors even if page contains nulls
                        current_candidate["end_sector"] = s_idx
                        current_candidate["byte_length"] = (offset + len(sector_bytes)) - current_candidate["byte_offset"]
                        if current_candidate["byte_length"] >= current_candidate["expected_total_len"]:
                            current_candidate["byte_length"] = current_candidate["expected_total_len"]
                            current_candidate["has_valid_footer"] = True
                            raw_fragments.append(current_candidate)
                            current_candidate = None
                    else:
                        raw_fragments.append(current_candidate)
                        current_candidate = None
            else:
                is_txt, mime, cat = detect_text_heuristics(sector_bytes)
                if current_candidate:
                    # Extend current candidate
                    current_candidate["end_sector"] = s_idx
                    current_candidate["byte_length"] = (offset + len(sector_bytes)) - current_candidate["byte_offset"]
                    if current_candidate.get("expected_total_len"):
                        if current_candidate["byte_length"] >= current_candidate["expected_total_len"]:
                            current_candidate["byte_length"] = current_candidate["expected_total_len"]
                            current_candidate["has_valid_footer"] = True
                            raw_fragments.append(current_candidate)
                            current_candidate = None
                    elif current_candidate.get("expected_footer") and current_candidate["expected_footer"] in sector_bytes:
                        ftr = current_candidate["expected_footer"]
                        ftr_pos = sector_bytes.rfind(ftr)
                        if ftr_pos != -1:
                            current_candidate["byte_length"] = (offset + ftr_pos + len(ftr)) - current_candidate["byte_offset"]
                        current_candidate["has_valid_footer"] = True
                        raw_fragments.append(current_candidate)
                        current_candidate = None
                elif is_txt and cat:
                    # Start a text candidate
                    current_candidate = {
                        "start_sector": s_idx,
                        "end_sector": s_idx,
                        "byte_offset": offset,
                        "byte_length": len(sector_bytes),
                        "detected_type": mime or "text/plain",
                        "category": cat,
                        "description": f"Carved {cat.value}",
                        "expected_footer": None,
                        "has_valid_header": True,
                        "has_valid_footer": True,
                        "is_text": True
                    }

        if current_candidate:
            raw_fragments.append(current_candidate)

        # Fallback if disk image had zero recognized headers
        if not raw_fragments and total_bytes > 0:
            overall_entropy = calculate_entropy(raw_data)
            is_txt, mime, cat = detect_text_heuristics(raw_data[:2048])
            
            matched_magic = None
            for sig, smime, scat, sdesc, sfooter in MAGIC_SIGNATURES:
                if sig in raw_data[:2048]:
                    matched_magic = (sig, smime, scat, sdesc, sfooter)
                    break

            if matched_magic:
                sig, smime, scat, sdesc, sfooter = matched_magic
                raw_fragments.append({
                    "start_sector": 0,
                    "end_sector": total_sectors - 1,
                    "byte_offset": 0,
                    "byte_length": total_bytes,
                    "detected_type": smime,
                    "category": scat,
                    "description": sdesc,
                    "expected_footer": sfooter,
                    "has_valid_header": raw_data.startswith(sig),
                    "has_valid_footer": sfooter in raw_data if sfooter else False,
                    "is_text": False
                })
            elif is_txt and cat:
                raw_fragments.append({
                    "start_sector": 0,
                    "end_sector": total_sectors - 1,
                    "byte_offset": 0,
                    "byte_length": total_bytes,
                    "detected_type": mime or "text/plain",
                    "category": cat,
                    "description": f"Recovered {cat.value}",
                    "expected_footer": None,
                    "has_valid_header": False,
                    "has_valid_footer": False,
                    "is_text": True
                })
            else:
                detected_cat = FileCategory.IMAGE if overall_entropy > 6.5 else (FileCategory.DOCUMENT if overall_entropy > 3.0 else FileCategory.UNKNOWN)
                raw_fragments.append({
                    "start_sector": 0,
                    "end_sector": total_sectors - 1,
                    "byte_offset": 0,
                    "byte_length": total_bytes,
                    "detected_type": "image/jpeg" if overall_entropy > 6.5 else "application/octet-stream",
                    "category": detected_cat,
                    "description": f"Salvaged Stream ({detected_cat.value})",
                    "expected_footer": None,
                    "has_valid_header": False,
                    "has_valid_footer": False,
                    "is_text": False
                })

        return sector_map, raw_fragments
