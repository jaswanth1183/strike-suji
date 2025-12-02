import os
from typing import Dict, Any, List

OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

def analyze_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Lightweight analysis engine:
    - Produces human-readable findings based on simple heuristics.
    - If OPENAI_API_KEY is set, this function is a safe place to integrate LLM calls.
    """
    findings: List[str] = []
    # Port scan hints
    if 'open_ports' in report and report['open_ports']:
        for p in report['open_ports']:
            findings.append(f"Open port {p.get('port')} - service: {p.get('service')}")
        findings.append("Recommendation: Close unused ports or apply firewall rules.")
    # HTTP scan hints
    if report.get('requests'):
        for r in report['requests']:
            sc = r.get('status_code', 0)
            if sc >= 500:
                findings.append(f"Server error at {r.get('url')} (status {sc}). Investigate logs.")
            if sc == 200 and r.get('content_length',0) < 50:
                findings.append(f"Very small response at {r.get('url')} - could be a redirect or minimal page.")
            hdrs = r.get('headers',{})
            if 'server' in hdrs:
                findings.append(f"Server header exposes: {hdrs.get('server')}")
    if not findings:
        findings.append("No obvious issues detected by heuristics.")
    # If an API key is present, you could implement an LLM summary here; omitted for safety.
    return {"findings": findings, "notes": "Heuristic analysis only. For full LLM-based analysis set OPENAI_API_KEY and extend ai.analyze.py"}
