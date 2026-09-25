import io
import struct
from PIL import Image, ImageDraw
from typing import Tuple, Dict, Any

def create_synthetic_jpeg() -> bytes:
    """Generates a small valid JPEG image in memory for testing."""
    img = Image.new("RGB", (128, 128), color=(30, 144, 255))
    draw = ImageDraw.Draw(img)
    draw.rectangle([20, 20, 108, 108], fill=(255, 69, 0), outline=(255, 255, 255))
    draw.text((32, 54), "EVIDENCE", fill=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85)
    return buf.getvalue()

def create_synthetic_sqlite_page() -> bytes:
    """Creates a raw SQLite B-tree leaf page (512 bytes) containing simulated user transaction records."""
    page = bytearray(512)
    # Page header: 0x0D (leaf table page), freeblock=0, cell_count=3, cell_content_start=380, frag_free_bytes=0
    page[0] = 0x0D
    struct.pack_into(">H", page, 1, 0)
    struct.pack_into(">H", page, 3, 3) # 3 records
    struct.pack_into(">H", page, 5, 380) # start of cells
    page[7] = 0

    # Pointers to cells
    cell_offsets = [460, 420, 380]
    for i, offset in enumerate(cell_offsets):
        struct.pack_into(">H", page, 8 + (i * 2), offset)

    # Insert cell data (strings representing database rows)
    records = [
        b"ROW #101: Alice Vance | $14,500.00 | alice.vance@blackmesa-gov.us | APPROVED",
        b"ROW #102: Dr. Gordon Freeman | $92,000.00 | gfreeman@mit.edu | WIRE_PENDING",
        b"ROW #103: Barney Calhoun | $3,200.00 | bcalhoun@blackmesa-gov.us | CLEARED"
    ]
    for offset, rec in zip(cell_offsets, records):
        page[offset:offset + len(rec)] = rec

    return bytes(page)

class CorruptedStorageSimulator:
    """Generates realistic damaged storage media dumps (raw disk images) with fragmented files and bad sectors."""

    @classmethod
    def generate_simulated_disk_dump(cls, sector_size: int = 512, total_sectors: int = 64) -> Tuple[bytes, Dict[str, Any]]:
        """
        Synthesizes a 32 KB raw disk dump containing:
        - Sectors 0-3: Damaged MBR/Slack space (zeros & bad sector markers)
        - Sectors 4-7: Fragment 1 of Confidential Project Code (auth_service.py)
        - Sectors 8-10: Bad sectors (zeroed-out hardware cluster failure)
        - Sectors 11-13: Fragment 2 of Confidential Project Code (Continues Fragment 1 with AWS Secrets!)
        - Sectors 14-17: Financial Wire Transfer Contract (Legal document with emails, $ amounts)
        - Sectors 18-21: Corrupted SQLite Database (Header page wiped, B-tree leaf surviving!)
        - Sectors 22-25: Damaged Evidence JPEG Photo (Header clipped, compressed raster surviving)
        - Sectors 26-30: System Audit Logs with IP addresses and breach indicators
        - Sectors 31-63: Zero-padded unallocated drive sectors
        """
        raw_disk = bytearray(total_sectors * sector_size)

        # 1. Sector 4-7: Code Fragment 1
        code_part1 = (
            "# Module: core/auth_service.py\n"
            "# Confidential Internal Microservice - Unauthorized Access Prohibited\n"
            "import os, hmac, hashlib\n"
            "from typing import Optional, Dict\n\n"
            "class AuthenticationEngine:\n"
            "    def __init__(self, service_id: str = 'AUTH_NODE_01'):\n"
            "        self.service_id = service_id\n"
            "        self.db_cluster = 'prod-auth-db.internal.net'\n"
            "        self.active_sessions: Dict[str, dict] = {}\n\n"
            "    def verify_token(self, token_header: str) -> bool:\n"
            "        # Validate incoming bearer token\n"
            "        if not token_header.startswith('Bearer '):\n"
            "            return False\n"
        ).encode("utf-8")
        raw_disk[4 * sector_size : 4 * sector_size + len(code_part1)] = code_part1

        # 2. Sector 11-13: Code Fragment 2 (Continuations with secrets!)
        code_part2 = (
            "        raw_token = token_header.split(' ')[1]\n"
            "        # Master production API key and cryptographic salt\n"
            "        AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
            "        GITHUB_DEPLOY_TOKEN = 'ghp_49c30f78d389a421b9204018241ef49201ab'\n"
            "        JWT_SIGNING_SECRET = 's3cr3t_p@ssw0rd_h4sh_2026'\n"
            "        admin_email = 'security-ops@acmecorp-forensics.io'\n"
            "        return hmac.compare_digest(raw_token, JWT_SIGNING_SECRET)\n"
        ).encode("utf-8")
        raw_disk[11 * sector_size : 11 * sector_size + len(code_part2)] = code_part2

        # 3. Sector 14-17: Financial Contract Document
        contract_doc = (
            "CONFIDENTIAL SETTLEMENT & WIRE DISBURSEMENT AGREEMENT\n"
            "Date: 2026-03-14 10:30:00 UTC\n"
            "Parties: Apex Holdings LLC and CyberVanguard Solutions\n\n"
            "1. Escrow Release: The escrow agent is hereby instructed to disburse the sum of\n"
            "   $1,450,000.00 USD directly to account 0x71C8364437a9b1391655767b4582e0C1a086b978.\n"
            "2. Notice Address: All legal notices shall be sent to counsel at legal-compliance@apexholdings.org.\n"
            "3. Governing Jurisdiction: This agreement is executed under maritime commercial statutes.\n"
            "Authorized Signature: Marcus Vance, Chief Financial Officer.\n"
        ).encode("utf-8")
        raw_disk[14 * sector_size : 14 * sector_size + len(contract_doc)] = contract_doc

        # 4. Sector 18-21: Corrupted SQLite Database (Header page wiped with 0x00, leaf page placed at sector 19!)
        sqlite_leaf = create_synthetic_sqlite_page()
        raw_disk[19 * sector_size : 19 * sector_size + len(sqlite_leaf)] = sqlite_leaf

        # 5. Sector 22-25: Damaged JPEG Photo (Standard JPEG generated, then first 128 bytes stripped to simulate bad sectors)
        full_jpeg = create_synthetic_jpeg()
        # Corrupt the header: strip first 64 bytes and put remaining scanlines at sector 22
        damaged_jpeg_slice = full_jpeg[64:]
        raw_disk[22 * sector_size : 22 * sector_size + len(damaged_jpeg_slice)] = damaged_jpeg_slice

        # 6. Sector 26-30: System Audit Trail Logs
        audit_log = (
            "[2026-03-14 02:11:45] [INFO] systemd[1]: Started Security Audit Daemon.\n"
            "[2026-03-14 02:14:12] [WARN] pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.42  user=root\n"
            "[2026-03-14 02:14:15] [CRITICAL] IDS_ALERT: Potential brute force intrusion detected from IP 198.51.100.42.\n"
            "[2026-03-14 02:15:01] [INFO] Firewall rule auto-applied: DROP from 198.51.100.42 on port 22.\n"
            "[2026-03-14 02:16:30] [INFO] Admin session authenticated for user 'sysadmin@acmecorp-forensics.io'.\n"
        ).encode("utf-8")
        raw_disk[26 * sector_size : 26 * sector_size + len(audit_log)] = audit_log

        manifest = {
            "total_bytes": len(raw_disk),
            "sector_size": sector_size,
            "total_sectors": total_sectors,
            "simulated_scenarios": [
                "Fragmented Python Source Code across discontinuous sectors (4-7 and 11-13)",
                "Exposed High-Value AWS & GitHub Credentials in unallocated cluster",
                "Financial Settlement Contract with PII and Monetary Amounts",
                "Damaged SQLite Database with Wiped Header and Salvageable B-Tree Page",
                "Damaged JPEG Evidence Photo with Missing SOI/JFIF Header",
                "Security Audit Log with IDS Alerts and Attacker IP Addresses"
            ]
        }

        return bytes(raw_disk), manifest
