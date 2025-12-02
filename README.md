# HexStrike-AI (Scaffold)

This is a minimal, **safe** scaffold to jumpstart an AI-assisted security scanner.

**Important legal notice**: Only scan targets you own or have explicit permission to test. Unauthorized scanning is illegal.

## What is included
- FastAPI backend (`app.py`) with endpoints:
  - `POST /scan/http` body: { "url": "...", "paths": [...], "aggressive": false }
  - `POST /scan/port` body: { "host": "...", "ports": [80,443], "timeout": 1.0 }
- `scanners/http_scan.py` simple HTTP path enumeration using `requests`
- `scanners/port_scan.py` uses `python-nmap` (if nmap installed) or falls back to socket scanning
- `ai/analyze.py` simple heuristic analyzer. Optional OpenAI integration point via `OPENAI_API_KEY`.
- `requirements.txt` and a `Dockerfile`.

## How to run (local)
1. Install dependencies: `pip install -r requirements.txt`
2. Install `nmap` on your system for full port scanning features.
3. Run: `python app.py` or `uvicorn app:app --reload --host 0.0.0.0 --port 8000`

## Docker
Build and run:
```
docker build -t hexstrike-ai-scaffold .
docker run -p 8000:8000 --env OPENAI_API_KEY=... hexstrike-ai-scaffold
```

## Next steps I can do for you (pick any)
- Implement full LLM integration (OpenAI/Local LLM) to produce natural-language remediation for findings.
- Add Web UI (React) that calls the API and displays reports.
- Add more scanners (amass, subfinder, directory brute force) as safe wrappers.
- Harden the app (rate limits, auth, scanning quotas) for multiuser deployment.
