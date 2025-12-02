import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from scanners.http_scan import http_scan
from scanners.port_scan import port_scan
from ai.analyze import analyze_report
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="HexStrike-AI (Scaffold)", version="0.1")

class HTTPScanRequest(BaseModel):
    url: str
    paths: list[str] | None = None
    aggressive: bool = False

class PortScanRequest(BaseModel):
    host: str
    ports: list[int] | None = None
    timeout: float | None = 1.0

@app.post("/scan/http")
async def scan_http(req: HTTPScanRequest):
    # Security: enforce that user supplies a URL and warn about scanning external targets
    if not req.url.startswith(("http://","https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
    report = await http_scan(req.url, paths=req.paths, aggressive=req.aggressive)
    analysis = analyze_report(report)
    return {"report": report, "analysis": analysis}

@app.post("/scan/port")
async def scan_port(req: PortScanRequest):
    report = port_scan(req.host, ports=req.ports, timeout=req.timeout)
    analysis = analyze_report(report)
    return {"report": report, "analysis": analysis}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)
