from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import tempfile
import shutil
from typing import Dict, Any
import uvicorn
import sys
import logging
from contextlib import asynccontextmanager
import json
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

# Get the project root directory
PROJECT_ROOT = Path(__file__).parent.parent

import proteus
from python.analyzer import ProteusAnalyzer
from python.ml_detector import ProteusMLDetector
from python.yara_engine import ProteusYaraEngine

logging.getLogger("uvicorn.access").setLevel(logging.ERROR)

analyzer = ProteusAnalyzer()
ml_detector = ProteusMLDetector()
yara_engine = ProteusYaraEngine()


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n" + "=" * 45)
    print("  PROTEUS Web Dashboard Server")
    print("  FastAPI Backend v0.2.0")
    print("=" * 45 + "\n")

    try:
        ml_detector.load_model()
        print("[+] ML detector loaded")
    except Exception as e:
        print(f"[!] ML detector failed: {e}")

    try:
        if yara_engine.load_rules():
            print("[+] YARA engine loaded")
        else:
            print("[!] YARA rules not found")
    except Exception as e:
        print(f"[!] YARA engine failed: {e}")

    print("\n[*] Server running on http://localhost:8000")
    print("[*] Dashboard: http://localhost:8000\n")

    yield


app = FastAPI(title="PROTEUS API", version="0.2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(PROJECT_ROOT / "web")), name="static")


@app.get("/", response_class=HTMLResponse)
async def root():
    with open(PROJECT_ROOT / "web" / "index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/health")
async def health_check():
    return {
        "status": "online",
        "ml_loaded": ml_detector.rf_model is not None,
        "yara_loaded": yara_engine.compiled_rules is not None,
    }


@app.get("/api/stats")
async def get_stats():
    """Get system statistics including YARA rule count"""
    stats = {
        "ml_loaded": ml_detector.rf_model is not None,
        "yara_loaded": yara_engine.compiled_rules is not None,
        "yara_info": None,
    }

    if yara_engine.compiled_rules:
        try:
            stats["yara_info"] = yara_engine.get_rule_info()
        except Exception as e:
            print(f"[!] Error getting YARA info: {e}")
            stats["yara_info"] = {"rule_files": 0, "error": str(e)}

    return stats


@app.post("/api/scan")
async def scan_file(
    file: UploadFile = File(...),
    ml: str = Form("false"),
    yara: str = Form("false"),
    strings: str = Form("false"),
) -> Dict[str, Any]:
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    use_ml = ml.lower() == "true"
    use_yara = yara.lower() == "true"
    use_strings = strings.lower() == "true"

    # Accept all file types for analysis
    suffix = Path(file.filename).suffix if Path(file.filename).suffix else ".bin"

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        heuristic_result = analyzer.analyze_single(tmp_path)

        result = {
            "filename": file.filename,
            "size": Path(tmp_path).stat().st_size,
            "heuristic": heuristic_result,
        }

        if use_ml and ml_detector.rf_model:
            try:
                result["ml"] = ml_detector.predict(tmp_path)
            except Exception as e:
                print(f"[!] ML prediction error: {e}")
                result["ml"] = {"error": str(e)}

        if use_yara and yara_engine.compiled_rules:
            try:
                result["yara"] = yara_engine.scan_file(tmp_path)
            except Exception as e:
                print(f"[!] YARA scan error: {e}")
                result["yara"] = {"error": str(e)}

        if use_strings:
            try:
                strings_data = proteus.extract_strings_from_file(tmp_path)
                result["strings"] = {
                    "total_strings": strings_data.total_strings,
                    "encoded_strings": strings_data.encoded_strings,
                    "urls": strings_data.urls[:10],
                    "ips": strings_data.ips[:10],
                    "suspicious_strings": strings_data.suspicious_strings[:20],
                    "registry_keys": strings_data.registry_keys[:10],
                }
            except Exception as e:
                print(f"[!] String extraction error: {e}")
                result["strings"] = {"error": str(e)}

        return result

    except Exception as e:
        print(f"[!] Scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        try:
            Path(tmp_path).unlink()
        except:
            pass


def generate_html_report(data: Dict[str, Any]) -> str:
    """Generate HTML report from scan results"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Determine verdict and color
    heuristic = data.get("heuristic", {})
    threat_score = heuristic.get("score", 0)
    verdict = heuristic.get("verdict", "UNKNOWN")
    verdict_color = (
        "#ef4444"
        if verdict == "MALICIOUS"
        else "#10b981"
        if verdict == "CLEAN"
        else "#f59e0b"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PROTEUS Scan Report - {data.get("filename", "Unknown")}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f3f4f6; color: #1f2937; margin: 0; padding: 20px; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; }}
        .header h1 {{ margin: 0; font-size: 28px; display: flex; align-items: center; gap: 10px; }}
        .header .subtitle {{ opacity: 0.9; margin-top: 5px; }}
        .section {{ padding: 25px; border-bottom: 1px solid #e5e7eb; }}
        .section:last-child {{ border-bottom: none; }}
        .section h2 {{ color: #667eea; margin-top: 0; font-size: 20px; display: flex; align-items: center; gap: 10px; }}
        .verdict-box {{ display: inline-block; padding: 10px 20px; border-radius: 8px; font-weight: bold; font-size: 24px; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 15px; }}
        .info-item {{ background: #f9fafb; padding: 15px; border-radius: 8px; border-left: 3px solid #667eea; }}
        .info-label {{ color: #6b7280; font-size: 13px; margin-bottom: 5px; }}
        .info-value {{ color: #111827; font-weight: 600; font-size: 16px; }}
        .indicator {{ background: #fef3c7; color: #92400e; padding: 8px 12px; border-radius: 6px; margin: 5px; display: inline-block; font-size: 14px; }}
        .packer-box {{ background: #ffedd5; padding: 15px; border-radius: 8px; border-left: 3px solid #f97316; margin-top: 10px; }}
        .ml-box {{ background: #dbeafe; padding: 15px; border-radius: 8px; border-left: 3px solid #3b82f6; margin-top: 10px; }}
        .yara-match {{ background: #fee2e2; padding: 12px; border-radius: 6px; margin-bottom: 10px; border-left: 3px solid #ef4444; }}
        .strings-box {{ background: #f3f4f6; padding: 10px; border-radius: 6px; max-height: 300px; overflow-y: auto; font-family: monospace; font-size: 13px; }}
        .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 13px; }}
        .icon {{ width: 24px; height: 24px; display: inline-block; vertical-align: middle; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #e5e7eb; }}
        th {{ background: #f9fafb; font-weight: 600; color: #374151; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>
                <svg class="icon" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M6.267 3.455a3.066 3.066 0 001.745-.723 3.066 3.066 0 013.976 0 3.066 3.066 0 001.745.723 3.066 3.066 0 012.812 2.812c.051.643.304 1.254.723 1.745a3.066 3.066 0 010 3.976 3.066 3.066 0 00-.723 1.745 3.066 3.066 0 01-2.812 2.812 3.066 3.066 0 00-1.745.723 3.066 3.066 0 01-3.976 0 3.066 3.066 0 00-1.745-.723 3.066 3.066 0 01-2.812-2.812 3.066 3.066 0 00-.723-1.745 3.066 3.066 0 010-3.976 3.066 3.066 0 00.723-1.745 3.066 3.066 0 012.812-2.812zm7.44 5.252a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                </svg>
                PROTEUS Malware Analysis Report
            </h1>
            <div class="subtitle">Advanced Threat Detection & Analysis Platform v0.2.0</div>
        </div>

        <div class="section">
            <h2>
                <svg class="icon" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M9 2a1 1 0 000 2h2a1 1 0 100-2H9z"/>
                    <path fill-rule="evenodd" d="M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5zm3 4a1 1 0 000 2h.01a1 1 0 100-2H7zm3 0a1 1 0 000 2h3a1 1 0 100-2h-3zm-3 4a1 1 0 100 2h.01a1 1 0 100-2H7zm3 0a1 1 0 100 2h3a1 1 0 100-2h-3z" clip-rule="evenodd"/>
                </svg>
                File Information
            </h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Filename</div>
                    <div class="info-value">{data.get("filename", "Unknown")}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">File Size</div>
                    <div class="info-value">{data.get("size", 0):,} bytes</div>
                </div>
                <div class="info-item">
                    <div class="info-label">File Type</div>
                    <div class="info-value">{heuristic.get("type", "Unknown")}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Scan Time</div>
                    <div class="info-value">{timestamp}</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>
                <svg class="icon" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                </svg>
                Analysis Verdict
            </h2>
            <div class="verdict-box" style="background-color: {verdict_color}; color: white;">
                {verdict}
            </div>
            <div class="info-grid" style="margin-top: 20px;">
                <div class="info-item">
                    <div class="info-label">Threat Score</div>
                    <div class="info-value">{threat_score:.2f} / 100</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Entropy</div>
                    <div class="info-value">{heuristic.get("entropy", 0):.2f}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Imports</div>
                    <div class="info-value">{heuristic.get("import_count", 0)}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Exports</div>
                    <div class="info-value">{heuristic.get("export_count", 0)}</div>
                </div>
            </div>
        </div>"""

    # Suspicious indicators
    indicators = heuristic.get("indicators", [])
    if indicators:
        html += """
        <div class="section">
            <h2>
                <svg class="icon" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
                </svg>
                Suspicious Indicators
            </h2>"""
        for indicator in indicators:
            html += f'<div class="indicator">{indicator}</div>'
        html += "</div>"

    # Packer detection
    packer = heuristic.get("packer", {})
    if packer and packer.get("detected"):
        html += f"""
        <div class="section">
            <h2>
                <svg class="icon" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"/>
                </svg>
                Packer Detection
            </h2>
            <div class="packer-box">
                <strong>Packer:</strong> {packer.get("name", "Unknown")}<br>
                <strong>Confidence:</strong> {packer.get("confidence", 0):.1f}%<br>"""
        if packer.get("indicators"):
            html += "<strong>Indicators:</strong><br>"
            for ind in packer.get("indicators", []):
                html += f"• {ind}<br>"
        html += "</div></div>"

    # ML Analysis
    if "ml" in data and not data["ml"].get("error"):
        ml = data["ml"]
        ml_verdict = ml.get("prediction", "unknown").upper()
        ml_color = "#ef4444" if ml_verdict == "MALICIOUS" else "#10b981"
        html += f"""
        <div class="section">
            <h2>
                <svg class="icon" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M6 6V5a3 3 0 013-3h2a3 3 0 013 3v1h2a2 2 0 012 2v3.57A22.952 22.952 0 0110 13a22.95 22.95 0 01-8-1.43V8a2 2 0 012-2h2zm2-1a1 1 0 011-1h2a1 1 0 011 1v1H8V5zm1 5a1 1 0 011-1h.01a1 1 0 110 2H10a1 1 0 01-1-1z" clip-rule="evenodd"/>
                    <path d="M2 13.692V16a2 2 0 002 2h12a2 2 0 002-2v-2.308A24.974 24.974 0 0110 15c-2.796 0-5.487-.46-8-1.308z"/>
                </svg>
                Machine Learning Analysis
            </h2>
            <div class="ml-box">
                <strong style="color: {ml_color};">Prediction: {ml_verdict}</strong><br>
                <strong>Confidence:</strong> {ml.get("confidence", 0) * 100:.1f}%
            </div>
        </div>"""

    # YARA Analysis
    if "yara" in data and data["yara"].get("match_count", 0) > 0:
        yara = data["yara"]
        html += f"""
        <div class="section">
            <h2>
                <svg class="icon" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd"/>
                </svg>
                YARA Rules Matched ({yara.get("match_count", 0)})
            </h2>"""
        for match in yara.get("matches", []):
            meta = match.get("meta", {})
            html += f"""
            <div class="yara-match">
                <strong>{match.get("rule", "Unknown")}</strong><br>"""
            if meta.get("description"):
                html += f"<em>{meta['description']}</em><br>"
            if meta.get("author"):
                html += f"<small>Author: {meta['author']}</small><br>"
            html += "</div>"
        html += "</div>"

    # Strings analysis
    if "strings" in data and not data["strings"].get("error"):
        strings = data["strings"]
        html += f"""
        <div class="section">
            <h2>
                <svg class="icon" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm2 6a1 1 0 011-1h6a1 1 0 110 2H7a1 1 0 01-1-1zm1 3a1 1 0 100 2h6a1 1 0 100-2H7z" clip-rule="evenodd"/>
                </svg>
                String Analysis
            </h2>
            <table>
                <tr><th>Category</th><th>Count</th></tr>
                <tr><td>Total Strings</td><td>{strings.get("total_strings", 0)}</td></tr>
                <tr><td>Encoded Strings</td><td>{strings.get("encoded_strings", 0)}</td></tr>
                <tr><td>URLs Found</td><td>{len(strings.get("urls", []))}</td></tr>
                <tr><td>IP Addresses</td><td>{len(strings.get("ips", []))}</td></tr>
                <tr><td>Suspicious Strings</td><td>{len(strings.get("suspicious_strings", []))}</td></tr>
                <tr><td>Registry Keys</td><td>{len(strings.get("registry_keys", []))}</td></tr>
            </table>"""

        if strings.get("suspicious_strings"):
            html += '<h3 style="margin-top: 20px;">Suspicious Strings</h3><div class="strings-box">'
            for s in strings.get("suspicious_strings", [])[:20]:
                html += f"{s}<br>"
            html += "</div>"

        html += "</div>"

    html += f"""
        <div class="footer">
            Generated by PROTEUS v0.2.0 on {timestamp}<br>
            Advanced Malware Analysis Platform
        </div>
    </div>
</body>
</html>"""
    return html


@app.post("/api/export")
async def export_results(
    format: str = Form(...), data: str = Form(...)
) -> FileResponse:
    """Export scan results in specified format (json, html, pdf)"""
    try:
        # Parse the JSON data
        scan_data = json.loads(data)
        filename_base = scan_data.get("filename", "scan_result").replace(" ", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format == "json":
            # JSON export
            output_file = (
                Path(tempfile.gettempdir()) / f"{filename_base}_{timestamp}.json"
            )
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(scan_data, f, indent=2, ensure_ascii=False)

            return FileResponse(
                path=str(output_file),
                filename=f"{filename_base}_{timestamp}.json",
                media_type="application/json",
            )

        elif format == "html":
            # HTML export
            html_content = generate_html_report(scan_data)
            output_file = (
                Path(tempfile.gettempdir()) / f"{filename_base}_{timestamp}.html"
            )
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)

            return FileResponse(
                path=str(output_file),
                filename=f"{filename_base}_{timestamp}.html",
                media_type="text/html",
            )

        elif format == "pdf":
            # PDF export requires additional library
            raise HTTPException(
                status_code=501,
                detail="PDF export requires weasyprint or reportlab installation",
            )

        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON data")
    except Exception as e:
        print(f"[!] Export error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, log_level="error")
