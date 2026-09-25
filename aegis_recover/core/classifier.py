import re
from typing import List, Dict, Tuple, Optional, Any
from .types import FileCategory, PriorityLevel, ExtractedEntity, RecoveredFragment

# Forensic Entity Patterns
PATTERNS = {
    "api_key": [
        (r"(?:api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token)[\s:=]+['\"]?([A-Za-z0-9_\-]{16,64})['\"]?", 0.95),
        (r"ghp_[A-Za-z0-9]{36}", 0.99),  # GitHub personal token
        (r"AKIA[0-9A-Z]{16}", 0.99),       # AWS Access Key
        (r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", 0.90), # JWT
    ],
    "private_key": [
        (r"-----BEGIN (?:RSA )?PRIVATE KEY-----", 0.99),
        (r"-----BEGIN OPENSSH PRIVATE KEY-----", 0.99),
    ],
    "email": [
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b", 0.95),
    ],
    "phone": [
        (r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", 0.80),
    ],
    "ip_address": [
        (r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", 0.85),
    ],
    "monetary_amount": [
        (r"\$\s?[0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{2})?", 0.88),
        (r"(?:USD|EUR|GBP|INR)\s?[0-9]+(?:\.[0-9]{2})?", 0.88),
    ],
    "timestamp": [
        (r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b", 0.90),
    ],
    "crypto_address": [
        (r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", 0.85), # BTC
        (r"\b0x[a-fA-F0-9]{40}\b", 0.90), # ETH
    ],
    "db_table": [
        (r"(?:FROM|JOIN|TABLE|INTO)\s+[`\"]?([A-Za-z0-9_]{3,32})[`\"]?", 0.75),
    ]
}

class SemanticClassifier:
    """Extracts forensic entities, categorizes unstructured fragments, and generates AI summaries."""

    def extract_entities(self, text: str) -> List[ExtractedEntity]:
        """Scans extracted text for high-value forensic entities."""
        entities: List[ExtractedEntity] = []
        seen = set()

        for entity_type, pattern_list in PATTERNS.items():
            for pattern, base_conf in pattern_list:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    val = match.group(1) if match.groups() else match.group(0)
                    val = val.strip()
                    if len(val) > 2 and (entity_type, val) not in seen:
                        seen.add((entity_type, val))
                        entities.append(ExtractedEntity(
                            entity_type=entity_type,
                            value=val,
                            confidence=base_conf
                        ))
        return entities

    def analyze_fragment(self, raw_bytes: bytes, mime_type: str, category: FileCategory) -> Dict[str, Any]:
        """
        Deep semantic analysis of fragment payload.
        Returns extracted entities, AI-generated summary, forensic tags, and priority assessment.
        """
        cleaned_bytes = raw_bytes.strip(b"\x00")
        text_content = ""
        is_textual = False
        
        try:
            text_content = cleaned_bytes.decode("utf-8", errors="ignore")
            printable = sum(1 for c in text_content if c.isprintable() or c in "\r\n\t")
            if len(text_content) > 0 and (printable / len(text_content)) > 0.65:
                is_textual = True
        except Exception:
            try:
                text_content = cleaned_bytes.decode("latin-1", errors="ignore")
                printable = sum(1 for c in text_content if c.isprintable() or c in "\r\n\t")
                if len(text_content) > 0 and (printable / len(text_content)) > 0.65:
                    is_textual = True
            except Exception:
                is_textual = False

        entities: List[ExtractedEntity] = []
        tags: List[str] = []
        summary = ""
        priority = PriorityLevel.MEDIUM

        if is_textual and text_content:
            entities = self.extract_entities(text_content)

            # Check for critical security tokens
            has_credentials = any(e.entity_type in ["api_key", "private_key"] for e in entities)
            has_financial = any(e.entity_type in ["monetary_amount", "crypto_address"] for e in entities)
            has_pii = any(e.entity_type in ["email", "phone"] for e in entities)

            if has_credentials or has_financial:
                priority = PriorityLevel.CRITICAL
                tags.append("HIGH_VALUE_INTEL")
                if has_credentials:
                    tags.append("CREDENTIALS_EXPOSED")
                if has_financial:
                    tags.append("FINANCIAL_RECORDS")
            elif has_pii:
                priority = PriorityLevel.HIGH
                tags.append("PII_DETECTED")
            elif category == FileCategory.SOURCE_CODE:
                priority = PriorityLevel.HIGH
                tags.append("CODEBASE_INTEL")
            elif category == FileCategory.DATABASE:
                priority = PriorityLevel.HIGH
                tags.append("DATABASE_SCHEMA_DATA")
            elif category == FileCategory.SYSTEM_LOG:
                priority = PriorityLevel.MEDIUM
                tags.append("AUDIT_TRAIL")
            else:
                priority = PriorityLevel.LOW

            # Synthesize intelligent summary
            first_lines = [l.strip() for l in text_content.split("\n") if l.strip()][:3]
            sample = " | ".join(first_lines)[:180]
            summary = f"Textual fragment ({len(text_content)} chars). Sample: \"{sample}\"."
            if entities:
                summary += f" Extracted {len(entities)} forensic entities ({', '.join(set(e.entity_type for e in entities))})."
        else:
            # Binary fragment analysis
            if category == FileCategory.IMAGE:
                priority = PriorityLevel.HIGH
                tags.append("MEDIA_ARTIFACT")
                summary = f"Binary media stream ({mime_type}, {len(raw_bytes)} bytes). Contains raw raster/compressed scanlines."
            elif category == FileCategory.DATABASE:
                priority = PriorityLevel.CRITICAL
                tags.append("RAW_DATABASE_PAGES")
                summary = f"Raw database block ({len(raw_bytes)} bytes). Potential B-tree structure or transaction journal."
            elif category == FileCategory.ARCHIVE:
                priority = PriorityLevel.HIGH
                tags.append("COMPRESSED_CONTAINER")
                summary = f"Compressed archive container ({len(raw_bytes)} bytes). May encapsulate bundled files/documents."
            elif category == FileCategory.DOCUMENT:
                priority = PriorityLevel.HIGH
                tags.append("DOCUMENT_FRAGMENT")
                summary = f"Document payload ({len(raw_bytes)} bytes). Header markers identified."
            else:
                priority = PriorityLevel.LOW
                summary = f"Unstructured binary chunk ({len(raw_bytes)} bytes)."

        return {
            "entities": entities,
            "priority": priority,
            "tags": tags,
            "summary": summary,
            "is_textual": is_textual,
            "text_sample": text_content[:500] if is_textual else None
        }
