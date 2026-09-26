import argparse
import sys
import os
import uvicorn

def main():
    parser = argparse.ArgumentParser(
        description="AegisRecover AI: Autonomous Deep Sector Carving, Reconstruction & Forensic Relationship Engine"
    )
    parser.add_argument("--serve", action="store_true", default=True, help="Launch FastAPI web server and GUI dashboard (default)")
    parser.add_argument("--benchmark", action="store_true", help="Execute synthetic damaged drive benchmark in CLI")
    parser.add_argument("--scan", type=str, help="Path to raw disk dump (.dd, .raw, .img) or corrupted file to scan")
    parser.add_argument("--port", type=int, default=8000, help="Server port (default: 8000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1)")

    args = parser.parse_args()

    if args.benchmark:
        from test_engine import run_forensic_recovery_test
        run_forensic_recovery_test()
        sys.exit(0)

    if args.scan:
        if not os.path.exists(args.scan):
            print(f"[!] Error: File '{args.scan}' not found.")
            sys.exit(1)
        print(f"[+] Loading raw storage: {args.scan} ...")
        with open(args.scan, "rb") as f:
            data = f.read()
        from aegis_recover.core import RecoveryEngine
        engine = RecoveryEngine(sector_size=512)
        report = engine.process_raw_storage(data, source_name=os.path.basename(args.scan))
        print(f"[+] Scan Complete: {report.scan_id}")
        print(f"    Total Fragments: {len(report.fragments)}")
        print(f"    Avg Recoverability: {report.stats['average_recoverability_pct']}%")
        print(f"    Relationships: {len(report.relationships)}")
        sys.exit(0)

    # Launch Server
    print("=" * 75)
    print(">>> STARTING AEGISRECOVER AI SERVER")
    print(f">>> Web Dashboard: http://{args.host}:{args.port}")
    print(f">>> API Swagger Docs: http://{args.host}:{args.port}/docs")
    print("=" * 75)
    uvicorn.run("aegis_recover.api.server:app", host=args.host, port=args.port, reload=False)

if __name__ == "__main__":
    main()
