import io
import os
import json
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import Response, JSONResponse

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
        ]
    }

@router.post("/scan/simulate")
def run_simulation_benchmark():
    """Generates a realistic damaged disk image with multi-sector corruption and runs recovery."""
    raw_disk, manifest = CorruptedStorageSimulator.generate_simulated_disk_dump(sector_size=512, total_sectors=64)
    report = engine.process_raw_storage(raw_disk, source_name="simulated_damaged_drive.dd")
    
    SCANS_DB[report.scan_id] = report
    RAW_IMAGE_STORE[report.scan_id] = raw_disk
    
    # Return report as JSON dictionary
    return json.loads(report.model_dump_json(exclude={"fragments": {"__all__": {"reconstructed_bytes"}}}))

@router.post("/scan/upload")
async def upload_and_scan_storage(file: UploadFile = File(...)):
    """Uploads a damaged disk image or corrupted file for AI-assisted carving & recovery."""
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    report = engine.process_raw_storage(content, source_name=file.filename or "uploaded_image.dd")
    SCANS_DB[report.scan_id] = report
    RAW_IMAGE_STORE[report.scan_id] = content

    return json.loads(report.model_dump_json(exclude={"fragments": {"__all__": {"reconstructed_bytes"}}}))

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
            "average_recoverability_pct": r.stats.get("average_recoverability_pct", 0)
        })
    return summaries

@router.get("/scan/{scan_id}")
def get_scan_details(scan_id: str):
    """Retrieves complete forensic report for a specific scan."""
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
    report = SCANS_DB[scan_id]
    return json.loads(report.model_dump_json(exclude={"fragments": {"__all__": {"reconstructed_bytes"}}}))

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

    # Sort selected fragments by start sector
    selected_frags.sort(key=lambda f: f.start_sector)

    stitched_bytes = bytearray()
    stitch_logs = []
    for i in range(len(selected_frags) - 1):
        f_a = selected_frags[i]
        f_b = selected_frags[i + 1]
        b_a = f_a.reconstructed_bytes or b""
        b_b = f_b.reconstructed_bytes or b""
        res_bytes, conf, exp = engine.reconstructor.stitch_fragments(b_a, b_b)
        stitch_logs.append(f"Stitched {f_a.fragment_id} + {f_b.fragment_id}: {exp} (Confidence: {conf*100:.0f}%)")
        if i == 0:
            stitched_bytes.extend(res_bytes)
        else:
            stitched_bytes.extend(b_b)

    stitched_id = f"STITCHED_{selected_frags[0].fragment_id}_{selected_frags[-1].fragment_id}"
    
    # Create synthetic recovered fragment for export
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
        suggested_filename=f"stitched_recovery_{selected_frags[0].category.value.lower()}{selected_frags[0].suggested_filename[selected_frags[0].suggested_filename.rfind('.'):]}",
        summary=f"Reconstructed chain combining {len(selected_frags)} fragments.",
        reconstruction_notes=stitch_logs,
        reconstructed_bytes=bytes(stitched_bytes)
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
