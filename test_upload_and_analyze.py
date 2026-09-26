import urllib.request
import json
import os
import mimetypes

url = "http://127.0.0.1:8000/api/scan/upload"
filepath = os.path.abspath("corrupted_sample_disk.dd")
filename = os.path.basename(filepath)

boundary = "----AegisRecoverFormBoundary7MA4YWxkTrZu0gW"

with open(filepath, "rb") as f:
    file_bytes = f.read()

body = bytearray()
body.extend(f"--{boundary}\r\n".encode("utf-8"))
body.extend(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode("utf-8"))
body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
body.extend(file_bytes)
body.extend(f"\r\n--{boundary}--\r\n".encode("utf-8"))

req = urllib.request.Request(
    url,
    data=bytes(body),
    headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body))
    },
    method="POST"
)

print(f"Uploading '{filename}' ({len(file_bytes)} bytes) to {url}...")
with urllib.request.urlopen(req) as resp:
    status_code = resp.status
    resp_data = json.loads(resp.read().decode("utf-8"))

print("=" * 70)
print(f"UPLOAD & CARVING COMPLETED (HTTP Status: {status_code})")
print("=" * 70)
print(f"Scan ID: {resp_data.get('scan_id')}")
print(f"Source Storage Image: {resp_data.get('source_name')}")
print(f"Total Bytes Ingested: {resp_data.get('total_bytes')} bytes ({resp_data.get('total_sectors')} sectors)")
print(f"Local Storage Folder: {resp_data.get('saved_folder')}")

stats = resp_data.get("stats", {})
print("\n--- DAMAGE VS RECOVERY ACCOUNTING LEDGER ---")
print(f"Successfully Salvaged Data : {stats.get('recovered_bytes_formatted')} ({stats.get('recovery_pct')}%)")
print(f"Damaged / Corrupted Sectors : {stats.get('damaged_bytes_formatted')} ({stats.get('damaged_pct')}%)")
print(f"Zero Slack Space            : {stats.get('zero_slack_formatted')} ({stats.get('slack_pct')}%)")
print(f"Average Salvage Fidelity   : {stats.get('average_recoverability_pct')}%")
print(f"Executive Verdict          : {stats.get('executive_verdict')}")

gemini_rep = resp_data.get("gemini_report", {})
print("\n--- GEMINI AI FORENSIC VERIFICATION ---")
print(f"Verification Model : {gemini_rep.get('model')}")
print(f"Overall Status     : {gemini_rep.get('status')}")
print(f"Average Confidence : {gemini_rep.get('average_gemini_confidence')}%")
print(f"Verdict Summary    : {gemini_rep.get('executive_verdict')}")

frags = resp_data.get("fragments", [])
print(f"\n--- INVENTORY OF SALVAGED ARTIFACTS ({len(frags)} Files) ---")
for idx, f in enumerate(frags, 1):
    print(f"\n[{idx}] File: {f.get('suggested_filename')} (ID: {f.get('fragment_id')})")
    print(f"    Category        : {f.get('category')} | MIME: {f.get('detected_type')}")
    print(f"    Sectors         : {f.get('start_sector')} - {f.get('end_sector')} ({f.get('byte_length')} bytes)")
    print(f"    Integrity Status: {f.get('integrity_status')} | Fidelity: {f.get('recoverability_score')}%")
    
    g_verif = f.get("gemini_verification", {})
    if g_verif:
        print(f"    Gemini Status   : {g_verif.get('verification_status')} ({g_verif.get('confidence_score')}% confidence)")
        print(f"    Gemini Verdict  : {g_verif.get('forensic_verdict')}")
        
    entities = f.get("entities", [])
    if entities:
        print("    Forensic Entities Found:")
        for e in entities:
            print(f"      * [{e.get('entity_type')}] {e.get('value')}")
            
    notes = f.get("reconstruction_notes", [])
    if notes:
        print(f"    Reconstruction  : {notes[0]}")

# Write structured report to json
output_json_path = os.path.abspath("corrupted_file_analysis_result.json")
with open(output_json_path, "w", encoding="utf-8") as f_out:
    json.dump(resp_data, f_out, indent=2)

print("\nSaved full detailed JSON report to:", output_json_path)
