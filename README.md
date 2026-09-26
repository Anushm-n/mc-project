# AegisRecover AI: Autonomous Forensics & Intelligent Data Recovery Engine

AegisRecover AI is an AI-assisted digital forensics and data recovery solution designed to salvage, reconstruct, classify, and prioritize recoverable digital information from damaged, deleted, or partially corrupted storage media.

Unlike traditional file carvers (such as Scalpel or PhotoRec) that depend purely on static magic byte headers and continuous sectors, **AegisRecover AI** incorporates:
- **Shannon Entropy Sector Profiling**: Detects file transitions, encrypted blocks, and slack space even when headers are wiped.
- **Automated Structural Reconstruction & Header Synthesis**: Injects missing JFIF/DQT tables into damaged JPEGs, fixes PNG chunks, synthesizes PDF xref/trailers, and salvages raw SQLite B-Tree table leaf records even when page 0 is destroyed.
- **Forensic NLP & Entity Extraction**: Identifies high-value intelligence (AWS API keys, GitHub tokens, JWTs, private keys, PII, financial dollar transactions, crypto wallet addresses, timestamps, and IP addresses).
- **Inter-Fragment Relationship Graph**: Maps continuations across non-contiguous bad sectors, correlates shared organizational domains/entities, and links database schemas to data pages.
- **Recoverability Confidence Scoring (0 - 100%)**: Multi-dimensional scoring evaluating syntactic integrity, entropy alignment, null-byte density, and parser verification with actionable forensic prognoses.

---

## Architecture Overview

```
aegis_recover/
├── core/
│   ├── types.py            # Pydantic schemas, Enums (FileCategory, PriorityLevel, IntegrityStatus)
│   ├── scanner.py          # Sliding-window sector carver with Shannon entropy calculation
│   ├── classifier.py       # AI semantic classifier & forensic entity extractor (AWS, PII, Crypto, SQL)
│   ├── reconstructor.py    # Header synthesizer (JPEG, PNG, PDF, SQLite B-Tree records) & fragment stitcher
│   ├── integrity.py        # Recoverability Index (0-100%) & investigator diagnostic prognosis
│   ├── graph_engine.py     # Inter-fragment relationship graph (continuation, shared entities, clusters)
│   ├── simulator.py        # Synthetic damaged disk generator for instant testing & benchmarking
│   └── engine.py           # Master recovery orchestrator
├── api/
│   ├── routes.py           # FastAPI REST API endpoints
│   └── server.py           # Uvicorn server setup & static UI mount
├── static/
│   ├── index.html          # Cyber-Forensics analyst dashboard
│   ├── style.css           # Glassmorphism dark-mode UI
│   └── app.js              # Live sector heatmap, fragment viewer, hex dump & relationship graph
├── test_engine.py          # Benchmark test suite
├── run.py                  # CLI launcher and web server entry point
└── requirements.txt        # Python dependencies
```

---

## Quickstart

### 1. Launch the Web Dashboard & API Server
```powershell
python run.py --serve --port 8000
```
- **Web Dashboard**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### 2. Run the Benchmark in Terminal
```powershell
python run.py --benchmark
```

### 3. Scan an External Raw Storage Dump (.dd, .raw, .img)
```powershell
python run.py --scan path/to/damaged_disk.raw
```

---

## REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/status` | Engine health status and supported file formats |
| `POST` | `/api/scan/simulate` | Generates a damaged disk dump and executes full recovery pipeline |
| `POST` | `/api/scan/upload` | Uploads a `.dd`, `.raw`, `.img` disk image or corrupted file |
| `GET` | `/api/scans` | Lists all cached forensic scans |
| `GET` | `/api/scan/{id}` | Retrieves full scan report including sector map and fragments |
| `GET` | `/api/scan/{id}/fragment/{fid}` | Inspects a single fragment with hex dump and previews |
| `POST` | `/api/scan/{id}/stitch` | Stitches two or more fragments into a unified file |
| `GET` | `/api/export/{id}/{fid}` | Downloads the reconstructed, repaired file |
| `GET` | `/api/report/{id}/download` | Exports official JSON Forensic Audit Report |
