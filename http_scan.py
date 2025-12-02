import asyncio
from typing import List, Dict, Any
import requests
from urllib.parse import urljoin

COMMON_PATHS = [
    "/", "/robots.txt", "/.env", "/admin", "/login", "/.git/config",
    "/.well-known/security.txt", "/sitemap.xml", "/api/", "/.htaccess"
]

async def fetch(session, url):
    # simple wrapper using requests in threadpool for compatibility
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: requests.get(url, timeout=5, allow_redirects=True))

async def http_scan(url: str, paths: List[str] | None = None, aggressive: bool = False) -> Dict[str, Any]:
    results = {"url": url, "requests": [], "errors": []}
    target_paths = list(paths or []) + (COMMON_PATHS if not paths else [])
    # remove duplicates and ensure leading slash
    seen = set()
    final_paths = []
    for p in target_paths:
        if not p.startswith("/"):
            p = "/" + p
        if p not in seen:
            seen.add(p)
            final_paths.append(p)
    # limit if not aggressive
    if not aggressive:
        final_paths = final_paths[:10]
    tasks = []
    for p in final_paths:
        full = urljoin(url, p.lstrip("/"))
        tasks.append(fetch(None, full))
    for t in asyncio.as_completed(tasks):
        try:
            r = await t
            results["requests"].append({
                "url": r.url,
                "status_code": r.status_code,
                "content_length": len(r.content or b""),
                "headers": dict(r.headers),
            })
        except Exception as e:
            results["errors"].append(str(e))
    return results
