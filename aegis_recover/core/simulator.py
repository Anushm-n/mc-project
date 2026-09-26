import io
import struct
import random
from PIL import Image, ImageDraw
from typing import Tuple, Dict, Any, Optional

def create_synthetic_jpeg() -> bytes:
    """Generates a valid JPEG image in memory for testing."""
    img = Image.new("RGB", (128, 128), color=(30, 144, 255))
    draw = ImageDraw.Draw(img)
    draw.rectangle([20, 20, 108, 108], fill=(255, 69, 0), outline=(255, 255, 255))
    draw.text((32, 54), "EVIDENCE", fill=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85)
    return buf.getvalue()

def create_synthetic_sqlite_db() -> bytes:
    """Creates a valid SQLite database (8192 bytes) containing simulated user transaction records."""
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE transactions (id INTEGER PRIMARY KEY, user TEXT, amount REAL, email TEXT, status TEXT)")
    cur.execute("INSERT INTO transactions VALUES (101, 'Alice Vance', 14500.00, 'alice.vance@blackmesa-gov.us', 'APPROVED')")
    cur.execute("INSERT INTO transactions VALUES (102, 'Dr. Gordon Freeman', 92000.00, 'gfreeman@mit.edu', 'WIRE_PENDING')")
    cur.execute("INSERT INTO transactions VALUES (103, 'Barney Calhoun', 3200.00, 'bcalhoun@blackmesa-gov.us', 'CLEARED')")
    conn.commit()
    db_bytes = conn.serialize()
    conn.close()
    return db_bytes

class CorruptedStorageSimulator:
    """Generates realistic damaged storage media dumps with configurable damage profiles."""

    @classmethod
    def generate_simulated_disk_dump(
        cls,
        sector_size: int = 512,
        total_sectors: int = 64,
        profile: str = "MIXED_FORENSIC"
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Synthesizes a raw disk dump with specific customizable forensic scenarios:
        - "MIXED_FORENSIC": Realistic mix of fragmented code, credential leaks, damaged JPEGs, and wiped DB.
        - "RANSOMWARE_WIPE": File headers wiped with zero or pseudo-random entropy, but payloads survive.
        - "HEAD_CRASH": Severe continuous physical bad sectors with sparse surviving fragments.
        - "CREDENTIAL_LEAK": Unallocated memory and slack space with high-value API keys and private keys.
        """
        raw_disk = bytearray(total_sectors * sector_size)
        scenarios = []

        # 1. Code Fragment 1
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
            "        if not token_header.startswith('Bearer '):\n"
            "            return False\n"
        ).encode("utf-8")
        raw_disk[4 * sector_size : 4 * sector_size + len(code_part1)] = code_part1
        scenarios.append("Fragmented Python Source Code Part 1 (Sectors 4-5)")

        # 2. Code Fragment 2 (Discontinuous continuation)
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
        scenarios.append("Fragmented Python Source Code Part 2 with Exposed AWS/GitHub Secrets (Sector 11)")
        # 3. Financial Contract
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
        scenarios.append("Confidential Settlement Agreement with Monetary wire instructions (Sector 14)")

        # 4. Security Audit Logs
        audit_log = (
            "[2026-03-14 02:11:45] [INFO] systemd[1]: Started Security Audit Daemon.\n"
            "[2026-03-14 02:14:12] [WARN] pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.42  user=root\n"
            "[2026-03-14 02:14:15] [CRITICAL] IDS_ALERT: Potential brute force intrusion detected from IP 198.51.100.42.\n"
            "[2026-03-14 02:15:01] [INFO] Firewall rule auto-applied: DROP from 198.51.100.42 on port 22.\n"
            "[2026-03-14 02:16:30] [INFO] Admin session authenticated for user 'sysadmin@acmecorp-forensics.io'.\n"
        ).encode("utf-8")
        raw_disk[18 * sector_size : 18 * sector_size + len(audit_log)] = audit_log
        scenarios.append("Security Audit Logs with Attacker IP and Brute-force Intrusion Trail (Sector 18)")

        # 5. JPEG Evidence Photo (100% Valid Image)
        full_jpeg = create_synthetic_jpeg()
        raw_disk[22 * sector_size : 22 * sector_size + len(full_jpeg)] = full_jpeg
        scenarios.append("JPEG Forensic Photo with Evidence Watermark (Sectors 22-25)")

        # 6. SQLite Transaction Database (100% Valid Database)
        sqlite_db = create_synthetic_sqlite_db()
        raw_disk[30 * sector_size : 30 * sector_size + len(sqlite_db)] = sqlite_db
        scenarios.append("SQLite Database with User Transactions Table (Sectors 30-45)")

        # Inject profile-specific modifications
        if profile == "RANSOMWARE_WIPE":
            # Simulate ransomware: encrypt or overwrite starting 128 bytes of code/doc with marker
            for s in [4, 14]:
                raw_disk[s * sector_size : s * sector_size + 64] = b"[LOCKED_BY_AEGIS_RANSOM_SAMPLE_0xDEADBEEF]"
            scenarios.append("Simulated Ransomware Header Wipe applied to sectors 4, 14")
        elif profile == "HEAD_CRASH":
            # Zero out intermediate blocks heavily
            for s in range(50, min(80, total_sectors)):
                raw_disk[s * sector_size : (s + 1) * sector_size] = b"\xAA" * sector_size
            scenarios.append("Physical platter head crash simulation: bad sector patterns 0xAA")

        manifest = {
            "profile": profile,
            "total_bytes": len(raw_disk),
            "sector_size": sector_size,
            "total_sectors": total_sectors,
            "simulated_scenarios": scenarios
        }

        return bytes(raw_disk), manifest
