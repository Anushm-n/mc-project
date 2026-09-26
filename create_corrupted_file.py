import os
import io
from PIL import Image, ImageDraw

sector_size = 512
total_sectors = 32
disk = bytearray(total_sectors * sector_size)

# 1. Sector 0: Bad MBR / Corrupted boot record
disk[0:64] = b"CORRUPTED_MBR_BAD_SECTOR_0xDEADBEEF\x00\xFF\xAA\x55\x12\x34"

# 2. Sector 2-3: Financial wire transfer contract
contract = (
    "CONFIDENTIAL ASSET DISBURSEMENT & SETTLEMENT AGREEMENT\n"
    "Parties: CyberVanguard AI Security and Quantum Nexus Ltd\n"
    "Disbursement Amount: $3,450,000.00 USD\n"
    "Escrow Destination Account: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e\n"
    "Compliance Contact: compliance-wire@quantum-nexus.global\n"
    "Security Authorization Hash: SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
    "Authorized Signature: Marcus Vance, CFO\n"
).encode("utf-8")
disk[2 * sector_size : 2 * sector_size + len(contract)] = contract

# 3. Sector 5: Ransomware / Bad sector noise
disk[5 * sector_size : 5 * sector_size + 128] = b"[ENCRYPTED_BAD_SECTOR_0xDEADC0DE_DATA_LOST_CORRUPTION_NOISE]\xAA\xBB\xCC" * 2

# 4. Sector 8-9: Python Microservice Authentication code
code = (
    "# Module: core/cloud_vault_service.py\n"
    "import os, hmac, hashlib\n"
    "AWS_ACCESS_KEY_ID = 'AKIA5TREXAMPLECLOUD88'\n"
    "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
    "JWT_SECRET = 'super_classified_recovery_token_2026'\n"
    "ADMIN_EMAIL = 'security-incident@cybervanguard.corp'\n"
    "def verify_executive_signature(sig, payload):\n"
    "    return hmac.compare_digest(sig, hashlib.sha256(payload).hexdigest())\n"
).encode("utf-8")
disk[8 * sector_size : 8 * sector_size + len(code)] = code

# 5. Sector 12: Forensic Intrusion Audit Log
audit = (
    "[2026-03-24 14:22:01] [CRITICAL] IDS_SENSOR_04: Port scan detected from attacker IP 203.0.113.89 on port 443.\n"
    "[2026-03-24 14:22:15] [WARN] pam_unix(sshd:auth): 42 authentication failures for root from 203.0.113.89.\n"
    "[2026-03-24 14:23:00] [INFO] Firewall rule auto-dropped attacker 203.0.113.89.\n"
    "[2026-03-24 14:23:45] [INFO] Forensic evidence dump saved to vault.\n"
).encode("utf-8")
disk[12 * sector_size : 12 * sector_size + len(audit)] = audit

# 6. Sector 16-19: Valid Evidence JPEG photo
img = Image.new("RGB", (100, 100), color=(20, 120, 220))
draw = ImageDraw.Draw(img)
draw.rectangle([10, 10, 90, 90], fill=(220, 40, 40), outline=(255, 255, 255))
draw.text((18, 45), "CONFIDENTIAL", fill=(255, 255, 255))
buf = io.BytesIO()
img.save(buf, format="JPEG", quality=80)
jpeg_data = buf.getvalue()
disk[16 * sector_size : 16 * sector_size + len(jpeg_data)] = jpeg_data

file_path = os.path.abspath("corrupted_sample_disk.dd")
with open(file_path, "wb") as f:
    f.write(disk)
print("SUCCESS: Created corrupted file:", file_path, "Size:", len(disk), "bytes")
