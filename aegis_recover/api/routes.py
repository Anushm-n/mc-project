import io
import os
import json
import zipfile
import base64
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from fastapi.responses import Response, HTMLResponse

from aegis_recover.core import (
    RecoveryEngine, CorruptedStorageSimulator,
    ScanReport, RecoveredFragment
)

router = APIRouter(prefix="/api")

# In-memory scan cache
SCANS_DB: Dict[str, ScanReport] = {}
RAW_IMAGE_STORE: Dict[str, bytes] = {}
engine = RecoveryEngine(sector_size=512)

@router.get("/status")
def get_system_status():
    """Returns engine health and active scans count."""
    return {
        "status": "ONLINE",
        "system": "AegisRecover AI Forensic Engine v2.4",
        "sector_size": 512,
        "scans_cached": len(SCANS_DB),
        "supported_formats": [
            "Raw Disk Dumps (.dd, .raw, .img, .bin)",
            "JPEG / PNG / GIF / BMP / WEBP",
            "PDF / Legacy MS Office / OpenXML ZIP",
            "SQLite v3 Database Pages",
            "Source Code (Python, C, JS, Go)",
            "System Logs / Syslog / RFC822 Communications"
        ],
        "damage_profiles": [
            "MIXED_FORENSIC",
            "RANSOMWARE_WIPE",
            "HEAD_CRASH"
        ]
    }

@router.post("/scan/simulate")
def run_simulation_benchmark(profile: str = Query("MIXED_FORENSIC")):
    """Generates a realistic damaged disk image with custom corruption profile and runs recovery."""
    raw_disk, manifest = CorruptedStorageSimulator.generate_simulated_disk_dump(
        sector_size=512, total_sectors=64, profile=profile
    )
    report = engine.process_raw_storage(raw_disk, source_name=f"simulated_{profile.lower()}_drive.dd")
    
    SCANS_DB[report.scan_id] = report
    RAW_IMAGE_STORE[report.scan_id] = raw_disk
    
    return json.loads(report.model_dump_json(exclude={"fragments": {"__all__": {"reconstructed_bytes"}}}))

@router.post("/scan/upload")
async def upload_and_scan_storage(file: UploadFile = File(...)):
    """Uploads a damaged disk image or corrupted file for AI-assisted carving & recovery."""
    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file stream: {str(e)}")

    if not content or len(content) == 0:
        raise HTTPException(status_code=400, detail="The selected file is empty (0 bytes). Please upload a valid file or storage image with content.")

    try:
        source_filename = file.filename or "uploaded_storage.dd"
        report = engine.process_raw_storage(content, source_name=source_filename)
        SCANS_DB[report.scan_id] = report
        RAW_IMAGE_STORE[report.scan_id] = content

        return json.loads(report.model_dump_json(exclude={"fragments": {"__all__": {"reconstructed_bytes"}}}))
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Forensic carving error: {str(e)}")

@router.get("/scans")
def list_scans():
    """Lists summary of all executed forensic scans."""
    summaries = []
    for sid, r in SCANS_DB.items():
        summaries.append({
            "scan_id": r.scan_id,
            "source_name": r.source_name,
            "timestamp": r.timestamp,
            "total_sectors": r.total_sectors,
            "total_bytes": r.total_bytes,
            "fragments_found": len(r.fragments),
            "critical_intel_count": r.stats.get("critical_intel_count", 0),
            "average_recoverability_pct": r.stats.get("average_recoverability_pct", 0),
            "recovered_bytes_formatted": r.stats.get("recovered_bytes_formatted", "0 B"),
            "damaged_bytes_formatted": r.stats.get("damaged_bytes_formatted", "0 B")
        })
    return summaries

@router.get("/scan/{scan_id}")
def get_scan_details(scan_id: str):
    """Retrieves complete forensic report for a specific scan."""
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
    report = SCANS_DB[scan_id]
    return json.loads(report.model_dump_json(exclude={"fragments": {"__all__": {"reconstructed_bytes"}}}))

@router.post("/open-folder")
@router.post("/scan/{scan_id}/open-folder")
def open_saved_folder(scan_id: str = "latest"):
    """Opens the local saved recovery folder in Windows File Explorer."""
    import subprocess
    import sys
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    root_recovered_dir = os.path.join(base_dir, "recovered_files")
    os.makedirs(root_recovered_dir, exist_ok=True)

    storage_dir = os.path.join(base_dir, "recovered_storage", scan_id)
    if os.path.exists(root_recovered_dir):
        target_dir = root_recovered_dir
    elif os.path.exists(storage_dir):
        target_dir = storage_dir
    else:
        target_dir = base_dir

    abs_path = os.path.abspath(target_dir)
    try:
        if sys.platform == "win32":
            win_path = abs_path.replace("/", "\\")
            subprocess.Popen(f'explorer.exe "{win_path}"', shell=True)
            try:
                os.startfile(win_path)
            except Exception:
                pass
        elif sys.platform == "darwin":
            subprocess.Popen(["open", abs_path])
        else:
            subprocess.Popen(["xdg-open", abs_path])
        return {"status": "SUCCESS", "message": f"Opened folder: {abs_path}", "path": abs_path}
    except Exception as e:
        return {"status": "ERROR", "message": str(e), "path": abs_path}

@router.get("/gemini/status")
def get_gemini_status():
    """Retrieves active Gemini AI model configuration and status."""
    return engine.gemini_analyzer.get_status()

@router.post("/gemini/config")
def set_gemini_config(payload: dict):
    """Configures Google Gemini API Key."""
    key = payload.get("api_key", "").strip()
    if not key:
        raise HTTPException(status_code=400, detail="API Key cannot be empty.")
    engine.gemini_analyzer.set_api_key(key)
    return {"status": "SUCCESS", "message": "Gemini API Key configured and saved.", "details": engine.gemini_analyzer.get_status()}

def _fragment_recovery_state(fragment: RecoveredFragment) -> str:
    """Classifies fragment-level content into the available forensic recovery states."""
    status = getattr(fragment, "integrity_status", None)
    if status and status.value == "INTACT":
        return "INTACT"
    if fragment.recoverability_score >= 80 or (status and status.value == "RECOVERABLE"):
        return "RECOVERED"
    if fragment.recoverability_score >= 40 or (status and status.value == "PARTIALLY_CORRUPTED"):
        return "PARTIAL"
    return "UNRECOVERABLE"


def _decode_fragment_text(payload: bytes) -> str:
    """Safely decodes fragment bytes to text while preserving the actual recovered content."""
    if not payload:
        return ""
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return payload.decode(encoding)
        except UnicodeDecodeError:
            continue
    return payload.decode("latin-1", errors="replace")


@router.get("/scan/{scan_id}/document")
def get_document_reconstruction(scan_id: str):
    """Builds a logical document reconstruction from actual recovered fragment data only."""
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan ID not found.")

    report = SCANS_DB[scan_id]
    ordered = sorted(report.fragments, key=lambda f: (f.start_sector, f.byte_offset, f.fragment_id))
    relationship_strength = {}
    for rel in report.relationships:
        if rel.relationship_type == "CONTINUATION":
            relationship_strength[rel.source_id] = max(relationship_strength.get(rel.source_id, 0.0), rel.confidence)
            relationship_strength[rel.target_id] = max(relationship_strength.get(rel.target_id, 0.0), rel.confidence)

    ordered = sorted(
        ordered,
        key=lambda f: (
            f.start_sector,
            -(relationship_strength.get(f.fragment_id, 0.0)),
            f.byte_offset,
            f.fragment_id,
        )
    )

    blocks: List[Dict[str, str]] = []
    doc_parts: List[str] = []
    total_intact = 0
    total_recovered = 0
    total_unrecoverable = 0
    previous_end = None

    for index, frag in enumerate(ordered):
        payload = frag.reconstructed_bytes or b""
        text = _decode_fragment_text(payload)
        state = _fragment_recovery_state(frag)

        if previous_end is not None and frag.start_sector > previous_end:
            gap_bytes = max(0, (frag.start_sector - previous_end) * report.sector_size)
            if gap_bytes > 0:
                marker = "[DATA DAMAGED — NOT RECOVERABLE]"
                blocks.append({"kind": "UNRECOVERABLE", "label": "🔴 UNRECOVERABLE", "text": marker})
                doc_parts.append(marker)
                total_unrecoverable += gap_bytes

        if payload:
            if state == "INTACT":
                label = "🟢 INTACT"
                total_intact += len(payload)
            elif state == "RECOVERED":
                label = "🟡 RECOVERED"
                total_recovered += len(payload)
            elif state == "PARTIAL":
                label = "🟠 PARTIAL"
                total_recovered += len(payload)
            else:
                label = "🔴 UNRECOVERABLE"
                total_unrecoverable += len(payload)

            text = text.strip("\x00") or "[PARTIAL DATA — RECOVERY INCOMPLETE]"
            blocks.append({"kind": state, "label": label, "text": text})
            doc_parts.append(text)
        else:
            marker = "[DATA DAMAGED — NOT RECOVERABLE]" if state == "UNRECOVERABLE" else "[PARTIAL DATA — RECOVERY INCOMPLETE]"
            blocks.append({"kind": state, "label": "🔴 UNRECOVERABLE" if state == "UNRECOVERABLE" else "🟠 PARTIAL", "text": marker})
            doc_parts.append(marker)
            if state == "UNRECOVERABLE":
                total_unrecoverable += 1
            else:
                total_recovered += 1

        previous_end = max(frag.end_sector, previous_end if previous_end is not None else frag.end_sector)

    if not blocks:
        marker = "[DATA DAMAGED — NOT RECOVERABLE]"
        blocks = [{"kind": "UNRECOVERABLE", "label": "🔴 UNRECOVERABLE", "text": marker}]
        doc_parts = [marker]

    document_text = "\n\n".join(doc_parts)
    document_bytes = document_text.encode("utf-8")
    original_size = max(1, report.total_bytes)

    filename = os.path.basename(report.source_name or "reconstructed_document.txt")
    if not filename or "." not in filename:
        filename = "reconstructed_document.txt"

    return {
        "filename": filename,
        "source_name": report.source_name,
        "original_size": report.total_bytes,
        "original_size_formatted": report.stats.get("total_input_formatted", "0 B"),
        "intact_bytes": total_intact,
        "recovered_bytes": total_recovered,
        "available_payload_bytes": sum(len(fragment.reconstructed_bytes or b"") for fragment in ordered),
        "unrecoverable_bytes": total_unrecoverable,
        "recovery_pct": report.stats.get("recovery_pct", 0),
        "document_text": document_text,
        "document_bytes_base64": base64.b64encode(document_bytes).decode("ascii"),
        "blocks": blocks,
    }


@router.get("/scan/{scan_id}/document/download")
def download_document_reconstruction(scan_id: str):
    """Downloads the reconstructed document as a plain-text file using actual recovered bytes."""
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan ID not found.")

    report = SCANS_DB[scan_id]
    recon = get_document_reconstruction(scan_id)
    payload = recon["document_text"].encode("utf-8")
    filename = recon["filename"] if recon.get("filename") else "reconstructed_document.txt"
    return Response(
        content=payload,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/scan/{scan_id}/document/pdf")
def export_document_reconstruction_pdf(scan_id: str):
    """Exports a minimal PDF version of the reconstructed document using the actual recovered text."""
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan ID not found.")

    recon = get_document_reconstruction(scan_id)
    text = recon["document_text"]
    if not text.strip():
        text = "[No recoverable text available in this scan]"

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    text_lines = []
    for line in lines:
        if len(line) > 90:
            for i in range(0, len(line), 90):
                text_lines.append(line[i:i + 90])
        else:
            text_lines.append(line)

    content_stream = "BT\n/F1 10 Tf\n50 760 Td\n"
    for idx, line in enumerate(text_lines[:180], start=1):
        escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        content_stream += f"1 0 0 1 0 {-idx * 12} Tm\n({escaped}) Tj\n"
    content_stream += "ET"

    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(content_stream.encode('latin-1'))} >>\nstream\n{content_stream}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n{obj}\nendobj\n".encode("latin-1"))

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
    pdf.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("latin-1"))

    filename = (recon.get("filename") or "reconstructed_document.txt").rsplit(".", 1)[0] + ".pdf"
    return Response(
        content=bytes(pdf),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/scan/{scan_id}/fragment/{fragment_id}")
def get_fragment_details(scan_id: str, fragment_id: str):
    """Retrieves deep forensic details and hex preview for a specific fragment."""
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
    report = SCANS_DB[scan_id]
    for frag in report.fragments:
        if frag.fragment_id == fragment_id:
            return json.loads(frag.model_dump_json(exclude={"reconstructed_bytes"}))
    raise HTTPException(status_code=404, detail="Fragment not found.")

@router.post("/scan/{scan_id}/stitch")
def stitch_fragments_endpoint(scan_id: str, payload: Dict[str, List[str]]):
    """
    Stitches two or more fragments together into a reconstructed file stream.
    Payload: {"fragment_ids": ["FRAG_0004_...", "FRAG_0011_..."]}
    """
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
    frag_ids = payload.get("fragment_ids", [])
    if len(frag_ids) < 2:
        raise HTTPException(status_code=400, detail="Provide at least 2 fragment IDs to stitch.")

    report = SCANS_DB[scan_id]
    frag_map = {f.fragment_id: f for f in report.fragments}
    selected_frags = [frag_map[fid] for fid in frag_ids if fid in frag_map]

    if len(selected_frags) != len(frag_ids):
        raise HTTPException(status_code=400, detail="One or more fragment IDs invalid.")

    selected_frags.sort(key=lambda f: f.start_sector)

    stitched_bytes = bytearray()
    stitch_logs = []
    for i in range(len(selected_frags) - 1):
        f_a = selected_frags[i]
        f_b = selected_frags[i + 1]
        b_a = f_a.reconstructed_bytes or b""
        b_b = f_b.reconstructed_bytes or b""
        res_bytes, conf, exp = engine.reconstructor.stitch_fragments(b_a, b_b)
        stitch_logs.append(f"Merged {f_a.fragment_id} + {f_b.fragment_id}: {exp} (Confidence: {conf*100:.0f}%)")
        if i == 0:
            stitched_bytes.extend(res_bytes)
        else:
            stitched_bytes.extend(b_b)

    ext = ".txt"
    if selected_frags[0].category.value == "SOURCE_CODE":
        ext = ".py"
    elif selected_frags[0].category.value == "DOCUMENT":
        ext = ".txt"
    elif selected_frags[0].category.value == "IMAGE":
        ext = ".jpg"

    stitched_id = f"STITCHED_{selected_frags[0].fragment_id}_{selected_frags[-1].fragment_id}"
    
    stitched_frag = RecoveredFragment(
        fragment_id=stitched_id,
        start_sector=selected_frags[0].start_sector,
        end_sector=selected_frags[-1].end_sector,
        byte_offset=selected_frags[0].byte_offset,
        byte_length=len(stitched_bytes),
        detected_type=selected_frags[0].detected_type,
        category=selected_frags[0].category,
        entropy=5.0,
        recoverability_score=85.0,
        suggested_filename=f"stitched_{selected_frags[0].fragment_id}_{selected_frags[-1].fragment_id}{ext}",
        summary=f"Reconstructed chain combining {len(selected_frags)} fragments.",
        reconstruction_notes=stitch_logs,
        reconstructed_bytes=bytes(stitched_bytes),
        raw_hex_preview="[Stitched multi-fragment stream: " + str(len(stitched_bytes)) + " bytes]"
    )
    report.fragments.append(stitched_frag)

    return {
        "stitched_fragment_id": stitched_id,
        "filename": stitched_frag.suggested_filename,
        "byte_length": len(stitched_bytes),
        "stitch_logs": stitch_logs
    }

@router.get("/export/{scan_id}/{fragment_id}")
def download_recovered_file(scan_id: str, fragment_id: str):
    """Downloads the reconstructed byte payload for a specific fragment."""
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
    report = SCANS_DB[scan_id]
    for frag in report.fragments:
        if frag.fragment_id == fragment_id:
            payload = frag.reconstructed_bytes or b""
            return Response(
                content=payload,
                media_type=frag.detected_type or "application/octet-stream",
                headers={
                    "Content-Disposition": f'attachment; filename="{frag.suggested_filename}"'
                }
            )
    raise HTTPException(status_code=404, detail="Fragment not found.")

@router.get("/export/{scan_id}/all/zip")
def download_all_recovered_files_zip(scan_id: str):
    """Packages all reconstructed files into a single ZIP archive along with an audit ledger."""
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
    report = SCANS_DB[scan_id]

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        # 1. Write each recovered artifact
        for frag in report.fragments:
            payload = frag.reconstructed_bytes or b""
            zip_file.writestr(f"recovered_files/{frag.suggested_filename}", payload)

        # 2. Write official audit summary ledger
        ledger_lines = [
            "=" * 70,
            f"AEGISRECOVER AI - OFFICIAL DATA SALVAGE & INTEGRITY REPORT",
            "=" * 70,
            f"Scan ID: {report.scan_id}",
            f"Source Storage: {report.source_name}",
            f"Timestamp: {report.timestamp}",
            f"Total Drive Input Size: {report.stats.get('total_input_formatted', '0 B')}",
            f"Successfully Recovered Data: {report.stats.get('recovered_bytes_formatted', '0 B')} ({report.stats.get('recovery_pct', 0)}%)",
            f"Damaged / Overwritten Sectors: {report.stats.get('damaged_bytes_formatted', '0 B')} ({report.stats.get('damaged_pct', 0)}%)",
            f"Zero Slack Space: {report.stats.get('zero_slack_formatted', '0 B')}",
            f"Average Structural Fidelity: {report.stats.get('average_recoverability_pct', 0)}%",
            f"Total Artifacts Salvaged: {len(report.fragments)}",
            "-" * 70,
            "INVENTORY OF SALVAGED ARTIFACTS:",
            "-" * 70
        ]
        for idx, f in enumerate(report.fragments, 1):
            ledger_lines.append(f"[{idx:02d}] {f.suggested_filename} | Sectors {f.start_sector}-{f.end_sector} | Fidelity: {f.recoverability_score}%")
            ledger_lines.append(f"     Type: {f.detected_type} | Category: {f.category.value}")
            if f.entities:
                ent_str = ", ".join(f"{e.entity_type.upper()}: {e.value}" for e in f.entities[:3])
                ledger_lines.append(f"     Entities: {ent_str}")
            ledger_lines.append(f"     Prognosis: {f.reconstruction_notes[0] if f.reconstruction_notes else 'Restored'}")
            ledger_lines.append("")

        zip_file.writestr("RECOVERY_AUDIT_LEDGER.txt", "\n".join(ledger_lines).encode("utf-8"))

    zip_buffer.seek(0)
    return Response(
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="aegis_recovered_bundle_{scan_id}.zip"'
        }
    )

@router.get("/report/{scan_id}/download")
def download_forensic_report_json(scan_id: str):
    """Downloads official JSON Forensic Audit Report."""
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
    report = SCANS_DB[scan_id]
    content = report.model_dump_json(indent=2, exclude={"fragments": {"__all__": {"reconstructed_bytes"}}})
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="forensic_report_{scan_id}.json"'
        }
    )

@router.get("/report/{scan_id}/html", response_class=HTMLResponse)
def get_forensic_report_html(scan_id: str):
    """Generates an official Forensic Investigation Certificate & Audit Dossier."""
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
    r = SCANS_DB[scan_id]

    frags_html = ""
    for f in r.fragments:
        entities_text = ", ".join(f"{e.entity_type.upper()}: {e.value}" for e in f.entities[:4]) if f.entities else "None"
        frags_html += f"""
        <tr style="border-bottom: 1px solid #e2e8f0;">
            <td style="padding: 10px; font-family: monospace;"><b>{f.fragment_id}</b></td>
            <td style="padding: 10px;">Sectors {f.start_sector}-{f.end_sector}</td>
            <td style="padding: 10px;">{f.category.value}</td>
            <td style="padding: 10px;"><b>{f.recoverability_score}%</b> ({f.integrity_status.value})</td>
            <td style="padding: 10px; font-size: 0.85em;">{entities_text}</td>
        </tr>
        """

    rels_html = ""
    for rel in r.relationships:
        rels_html += f"""
        <li style="margin-bottom: 6px;">
            <b>[{rel.relationship_type}]</b> {rel.source_id} &harr; {rel.target_id} (Confidence: {int(rel.confidence*100)}%): 
            <span>{rel.explanation}</span>
        </li>
        """

    stats = r.stats
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Forensic Dossier: {r.scan_id}</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #0f172a; padding: 40px; }}
            .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 16px rgba(0,0,0,0.06); }}
            h1 {{ color: #0284c7; margin-bottom: 4px; }}
            .meta {{ color: #64748b; font-size: 0.9em; margin-bottom: 24px; border-bottom: 2px solid #e2e8f0; padding-bottom: 16px; }}
            .ledger-cards {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 24px; }}
            .card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; }}
            .card-val {{ font-size: 1.4em; font-weight: bold; font-family: monospace; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
            th {{ background: #f1f5f9; padding: 10px; text-align: left; font-size: 0.85em; text-transform: uppercase; }}
            @media print {{ body {{ padding: 0; background: white; }} .container {{ box-shadow: none; }} button {{ display: none; }} }}
        </style>
    </head>
    <body>
        <div class="container">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h1>OFFICIAL FORENSIC RECOVERY AUDIT</h1>
                <button onclick="window.print()" style="padding:8px 16px; cursor:pointer; background:#0284c7; color:white; border:none; border-radius:6px; font-weight:600;">Print Dossier</button>
            </div>
            <div class="meta">
                <b>Scan ID:</b> {r.scan_id} &bull; <b>Source:</b> {r.source_name} &bull; <b>Date:</b> {r.timestamp}<br>
                <b>Total Input Storage:</b> {stats.get('total_input_formatted', '0 B')} &bull; <b>Total Sectors:</b> {r.total_sectors}
            </div>

            <div class="ledger-cards">
                <div class="card" style="border-left: 4px solid #10b981;">
                    <div style="font-size:0.8em; color:#64748b;">SALVAGED RECOVERED DATA</div>
                    <div class="card-val" style="color:#10b981;">{stats.get('recovered_bytes_formatted', '0 B')}</div>
                    <div style="font-size:0.8em;">{stats.get('recovery_pct', 0)}% of storage drive</div>
                </div>
                <div class="card" style="border-left: 4px solid #ef4444;">
                    <div style="font-size:0.8em; color:#64748b;">DAMAGED / CORRUPTED DATA</div>
                    <div class="card-val" style="color:#ef4444;">{stats.get('damaged_bytes_formatted', '0 B')}</div>
                    <div style="font-size:0.8em;">{stats.get('damaged_pct', 0)}% of storage drive</div>
                </div>
                <div class="card" style="border-left: 4px solid #64748b;">
                    <div style="font-size:0.8em; color:#64748b;">ZERO SLACK SPACE</div>
                    <div class="card-val" style="color:#64748b;">{stats.get('zero_slack_formatted', '0 B')}</div>
                    <div style="font-size:0.8em;">{stats.get('zero_sectors_count', 0)} unallocated sectors</div>
                </div>
            </div>

            <h3>SALVAGED ARTIFACT INVENTORY ({len(r.fragments)} Files)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Fragment ID</th>
                        <th>Sector Range</th>
                        <th>Type</th>
                        <th>Fidelity</th>
                        <th>Forensic Entities</th>
                    </tr>
                </thead>
                <tbody>
                    {frags_html}
                </tbody>
            </table>

            <h3 style="margin-top:32px;">RECONSTRUCTED RELATIONSHIPS & CONTINUATION CHAINS</h3>
            <ul>
                {rels_html if rels_html else "<li>No inter-fragment linkages detected.</li>"}
            </ul>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)
