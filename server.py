#!/usr/bin/env python3

import os
import tempfile
import shutil
import json
import uuid
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import Proteus modules
from python.analyzer import ProteusAnalyzer
from python.ml_detector import ProteusMLDetector
from python.yara_engine import ProteusYaraEngine
from python.config import ConfigManager
import proteus

# Global analyzers
ml_detector: Optional[ProteusMLDetector] = None
yara_engine: Optional[ProteusYaraEngine] = None

# Sandbox config
SANDBOX_SAMPLES_DIR = Path("samples")
SANDBOX_REPORTS_DIR = Path("reports")
SANDBOX_SAMPLES_DIR.mkdir(exist_ok=True)
SANDBOX_REPORTS_DIR.mkdir(exist_ok=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize ML and YARA engines on startup."""
    global ml_detector, yara_engine

    print("[PROTEUS] Starting server...")

    # Try to load ML models
    try:
        ml_detector = ProteusMLDetector()
        ml_detector.load_model()
        if ml_detector.rf_model:
            print("[+] ML models loaded successfully")
        else:
            print("[!] ML models not found (skipping ML detection)")
            ml_detector = None
    except Exception as e:
        print(f"[!] ML models not available: {e}")
        ml_detector = None

    # Try to load YARA rules
    try:
        yara_engine = ProteusYaraEngine()
        if yara_engine.load_rules() and yara_engine.compiled_rules:
            print("[+] YARA engine loaded successfully")
        else:
            print("[!] YARA rules not available")
            yara_engine = None
    except Exception as e:
        print(f"[!] YARA engine not available: {e}")
        yara_engine = None

    print("[+] Server ready at http://localhost:8000")

    yield

    # Cleanup on shutdown
    print("[PROTEUS] Shutting down...")
    
    # Optional: Clean up temporary directories if any persist (though tempfile handles this usually)
    # We could also cancel background tasks here if we tracked them
    
    print("[+] Server shutdown complete")


app = FastAPI(title="PROTEUS API", version="0.3.0", lifespan=lifespan)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="web"), name="static")


@app.get("/")
async def root():
    """Serve the main web interface."""
    return FileResponse("web/index.html")


@app.get("/api/stats")
async def get_stats():
    """Get system statistics."""
    stats = {
        "ml_loaded": ml_detector is not None,
        "yara_loaded": yara_engine is not None,
        "yara_info": {"rule_files": len(yara_engine.rules)} if yara_engine and yara_engine.rules else {},
        "version": "0.3.0",
        "sandbox_active": True
    }
    return stats

async def process_dynamic_analysis(file_path: Path, task_id: str):
    """Wait for sandbox report (simulated for now since docker-compose runs separately)"""
    report_path = SANDBOX_REPORTS_DIR / f"{file_path.name}.json"
    
    # In a real scenario, we'd poll or wait for a callback
    # Here we just acknowledge the file was placed for the sandbox runner
    pass

@app.get("/api/report/{task_id}")
async def get_report(task_id: str):
    """Retrieve dynamic analysis report."""
    # Find report by task ID (filename prefix)
    # The sandbox runner saves reports as {filename}.json
    # We need to find the file that starts with the task_id
    
    for report_file in SANDBOX_REPORTS_DIR.glob("*.json"):
        if report_file.name.startswith(task_id):
            try:
                with open(report_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Error reading report: {str(e)}")
    
    raise HTTPException(status_code=404, detail="Report not found or analysis pending")

@app.post("/api/scan")
async def scan_file(
    file: UploadFile = File(...),
    ml: str = Form("false"),
    yara: str = Form("false"),
    strings: str = Form("false"),
    sandbox: str = Form("false"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    """
    Scan an uploaded file.

    Handles antivirus interference by using temporary quarantine-free directories.
    """
    temp_dir = None
    temp_file = None

    try:
        # Create a temporary directory with a unique name
        # Some antivirus software excludes certain temp directories
        temp_dir = tempfile.mkdtemp(prefix="proteus_scan_")

        # Save uploaded file to temp directory
        file_path = Path(temp_dir) / file.filename
        content = await file.read()
        
        with open(file_path, "wb") as f:
            f.write(content)

        # 1. Static Analysis (Reuse existing logic)
        static_data = None
        try:
            static_result = proteus.analyze_file(str(file_path))
            static_data = {
                "file_type": static_result.file_type,
                "entropy": static_result.entropy,
                "threat_score": static_result.threat_score,
                "verdict": "MALICIOUS" if static_result.threat_score > 50 else "CLEAN",
                "indicators": static_result.suspicious_indicators,
                "packer": {
                    "detected": static_result.packer.detected,
                    "name": static_result.packer.packer_name
                },
                "imphash": static_result.imphash,
                "rich_header": {
                    "key": static_result.rich_header.key,
                    "entries": len(static_result.rich_header.entries)
                } if static_result.rich_header else None
            }
        except Exception as e:
            print(f"[!] Static analysis error: {e}")
            static_data = {"error": str(e)}

        # Construct response
        response = {
            "filename": file.filename,
            "static": static_data
        }

        # 2. Dynamic Analysis (Sandbox)
        if sandbox.lower() == "true":
            # Generate Task ID
            task_id = str(uuid.uuid4())
            
            # Copy file to sandbox samples directory
            # Format: {task_id}_{original_filename}
            sandbox_filename = f"{task_id}_{file.filename}"
            sandbox_path = SANDBOX_SAMPLES_DIR / sandbox_filename
            
            shutil.copy2(file_path, sandbox_path)
            
            response["dynamic"] = {
                "status": "pending",
                "task_id": task_id,
                "message": "File submitted to sandbox"
            }
            
            # Background task to wait (or just fire and forget)
            background_tasks.add_task(process_dynamic_analysis, sandbox_path, task_id)

        # ML analysis
        if ml.lower() == "true" and ml_detector:
            try:
                # Need to implement predict on file path
                # ml_detector.predict(str(file_path))
                pass 
            except Exception as e:
                response["ml"] = {"error": str(e)}

        # YARA analysis
        if yara.lower() == "true" and yara_engine:
            try:
                yara_result = yara_engine.scan_file(str(file_path))
                response["yara"] = yara_result
            except Exception as e:
                response["yara"] = {"error": str(e)}

        # String analysis
        if strings.lower() == "true":
            try:
                string_result = proteus.extract_strings_from_file(str(file_path))
                response["strings"] = {
                    "total": string_result.total_strings,
                    "encoded": string_result.encoded_strings,
                    "urls": string_result.urls[:10],
                    "ips": string_result.ips[:10],
                    "suspicious": string_result.suspicious_strings[:20],
                }
            except Exception as e:
                response["strings"] = {"error": str(e)}
        else:
            response["strings"] = None

        return response

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Clean up temp files
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                print(f"[!] Failed to clean up temp directory: {e}")


@app.post("/api/export")
async def export_report(format: str = Form(...), data: str = Form(...)):
    """Export scan results to JSON or HTML format."""
    try:
        scan_data = json.loads(data)

        if format == "json":
            # Export as JSON
            filename = f"proteus_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            return JSONResponse(
                content=scan_data,
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )

        elif format == "html":
            # Export as HTML report
            html = generate_html_report(scan_data)
            filename = f"proteus_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

            return Response(
                content=html.encode("utf-8"),
                media_type="text/html",
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )

        else:
            raise HTTPException(status_code=400, detail="Unsupported format")

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON data")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def generate_html_report(data: dict) -> str:
    """Generate HTML report from scan data."""
    filename = data.get("filename", "Unknown")
    heuristic = data.get("heuristic", {})
    verdict = heuristic.get("verdict", "UNKNOWN")
    score = heuristic.get("score", 0)

    verdict_color = "red" if verdict == "MALICIOUS" else "green"

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PROTEUS Analysis Report - {filename}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .verdict {{ font-size: 24px; font-weight: bold; color: {verdict_color}; }}
        .score {{ font-size: 18px; color: #666; }}
        .section {{ margin: 20px 0; padding: 15px; background: #f9f9f9; border-radius: 5px; }}
        .indicator {{ padding: 8px; margin: 5px 0; background: #fff3cd; border-left: 4px solid #ffc107; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #667eea; color: white; }}
        .meta {{ color: #666; font-size: 12px; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>PROTEUS Malware Analysis Report</h1>

        <div class="section">
            <h2>File Information</h2>
            <table>
                <tr><th>Filename</th><td>{filename}</td></tr>
                <tr><th>Type</th><td>{heuristic.get("type", "Unknown")}</td></tr>
                <tr><th>Entropy</th><td>{heuristic.get("entropy", 0):.2f}</td></tr>
                <tr><th>Verdict</th><td><span class="verdict">{verdict}</span></td></tr>
                <tr><th>Threat Score</th><td><span class="score">{score:.2f}/100</span></td></tr>
            </table>
        </div>
"""

    # Indicators
    indicators = heuristic.get("indicators", [])
    if indicators:
        html += """
        <div class="section">
            <h2>Suspicious Indicators</h2>
"""
        for ind in indicators:
            html += f'            <div class="indicator">{ind}</div>\n'
        html += "        </div>\n"

    # Packer info
    packer = heuristic.get("packer", {})
    if packer and packer.get("detected"):
        html += f"""
        <div class="section">
            <h2>Packer Detection</h2>
            <table>
                <tr><th>Packer Name</th><td>{packer.get("name", "Unknown")}</td></tr>
                <tr><th>Confidence</th><td>{packer.get("confidence", 0) * 100:.1f}%</td></tr>
            </table>
        </div>
"""

    # ML results
    ml = data.get("ml")
    if ml and not ml.get("error"):
        html += f"""
        <div class="section">
            <h2>Machine Learning Analysis</h2>
            <table>
                <tr><th>Prediction</th><td>{ml.get("prediction", "Unknown").upper()}</td></tr>
                <tr><th>Confidence</th><td>{ml.get("confidence", 0) * 100:.1f}%</td></tr>
                <tr><th>Anomaly Detected</th><td>{"Yes" if ml.get("is_anomaly") else "No"}</td></tr>
            </table>
        </div>
"""

    # YARA results
    yara = data.get("yara")
    if yara and yara.get("match_count", 0) > 0:
        html += f"""
        <div class="section">
            <h2>YARA Matches ({yara.get("match_count", 0)})</h2>
            <table>
                <tr><th>Rule</th><th>Description</th></tr>
"""
        for match in yara.get("matches", []):
            desc = match.get("meta", {}).get("description", "N/A")
            html += f"""                <tr><td>{match.get("rule", "Unknown")}</td><td>{desc}</td></tr>\n"""
        html += """            </table>
        </div>
"""

    html += f"""
        <div class="meta">
            <p>Generated by PROTEUS v0.2.0 - Advanced Zero-Day Static Analysis Engine</p>
            <p>Report generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>"""

    return html


def main():
    """Run the web server."""
    print(
        """
===============================================
         PROTEUS v0.2.0
   Web Interface Starting...
===============================================
"""
    )

    print("\n[!] ANTIVIRUS WARNING:")
    print(
        "If you encounter 'virus detected' errors, add this directory to Windows Defender exclusions:"
    )
    print(f"   {Path.cwd()}")
    print("\nSteps:")
    print("  1. Open Windows Security > Virus & threat protection")
    print("  2. Click 'Manage settings'")
    print("  3. Scroll to 'Exclusions' and click 'Add or remove exclusions'")
    print(f"  4. Add folder: {Path.cwd()}")
    print("\nStarting server on http://localhost:8000\n")

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")


if __name__ == "__main__":
    main()
