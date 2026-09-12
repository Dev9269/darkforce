import json
import os
import uuid
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import detect, link, net, seeds, stylo
from .collect import crawl_and_ingest
from .config import tor_available
from .db import DB
from .export import export as export_resp
from .tor import active_proxy

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "web")

db = DB()
app = FastAPI(title="DarkForce - Dark Web Threat Actor De-anonymization")

COLLECT_JOBS = {}


class SearchReq(BaseModel):
    q: str = ""
    kind: str = "all"


class ScanReq(BaseModel):
    url: str
    use_tor: bool = False


class CollectReq(BaseModel):
    source: str = "directory"
    use_tor: Optional[bool] = None


@app.get("/api/stats")
def stats():
    return db.stats()


@app.get("/api/search")
def search(q: str = "", kind: str = "all"):
    return db.search(q, kind)


@app.get("/api/actor/{aid}")
def actor(aid: int):
    a = db.actor_summary(aid)
    if not a:
        raise HTTPException(404, "actor not found")
    a["findings"] = []
    for h in a["handles"]:
        if h.get("site_id"):
            a["findings"] += db.findings_for_site(h["site_id"])
    a["stylo"] = stylo.match_handle(db, a["handles"][0]["handle"]) if a["handles"] else []
    return a


@app.get("/api/graph")
def graph(actor_id: int = 0):
    return db.graph(actor_id or None)


@app.get("/graph", response_class=Response)
def graph_view(min_conf: float = 0.0):
    """Standalone interactive entity graph (pyvis/vis.js). Color = node kind,
    edge thickness = confidence. &min_conf= filters weak links."""
    try:
        import pyvis.network as pv
    except ImportError:
        raise HTTPException(500, "pyvis not installed: pip install pyvis")

    g = db.graph()
    nodes, edges = g["nodes"], g["edges"]
    if min_conf > 0:
        edges = [e for e in edges if (e.get("w") or 0) >= min_conf]
        keep = {e["s"] for e in edges} | {e["t"] for e in edges}
        nodes = [n for n in nodes if n["id"] in keep]

    colors = {
        "actor": "#e74c3c", "handle": "#f39c12", "site": "#95a5a6",
        "btc": "#8e44ad", "xmr": "#9b59b6", "email": "#2ecc71",
        "pgp": "#3498db", "onion": "#7f8c8d", "enviro": "#1abc9c",
    }
    net = pv.Network(height="720px", width="100%", bgcolor="#0d1117",
                     font_color="#d1d5db", directed=False)
    net.barnes_hut(gravity=-8000, central_gravity=0.3, spring_length=140, spring_strength=0.04)
    for n in nodes:
        net.add_node(n["id"], label=n["label"], title=f"[{n['kind']}] {n['label']}",
                     color=colors.get(n["kind"], "#cccccc"))
    for e in edges:
        w = max(0.2, float(e.get("w") or 0.5))
        net.add_edge(e["s"], e["t"], value=w,
                     title=f"{e.get('e')} (conf {w:.2f})",
                     color="#3b82f6" if w >= 0.8 else "#6b7280")
    html = net.generate_html()
    return Response(content=html, media_type="text/html")


@app.get("/api/pg")
def pg_status():
    """Report which database backend is active (sqlite vs postgres)."""
    from .config import DATABASE_URL
    return {"backend": "postgres" if DATABASE_URL else "sqlite",
            "url": DATABASE_URL or "sqlite:///data/darkforce.db"}


@app.get("/api/misconfigs")
def misconfigs(severity: str = ""):
    rows = db.q("SELECT f.*, s.url site_url, s.title FROM findings f JOIN sites s ON s.id=f.site_id")
    if severity:
        rows = [r for r in rows if r["severity"] == severity]
    return [dict(r) for r in rows]


@app.get("/api/stylo/{handle}")
def stylo_for(handle: str):
    return stylo.match_handle(db, handle)


@app.get("/api/stylo")
def stylo_all():
    return stylo.match_all(db)[2]


@app.get("/api/timeline")
def timeline(start: str = "", end: str = ""):
    evs = [dict(r) for r in db.q("SELECT ts, handle, title, url, 'post' etype FROM posts"
                                 " WHERE (?='' OR ts>=?) AND (?='' OR ts<=?)", (start, start, end, end))]
    evs += [dict(r) for r in db.q("SELECT first_seen ts, detail title, url, 'finding' etype FROM findings"
                                  " WHERE (?='' OR first_seen>=?) AND (?='' OR first_seen<=?)", (start, start, end, end))]
    evs.sort(key=lambda e: e["ts"] or "", reverse=True)
    return evs


@app.post("/api/refresh")
def refresh():
    prof, pairs, per = stylo.match_all(db)
    res = link.rebuild_actors(db, stylo_pairs=pairs)
    return {**res, "stylo_pairs": len(pairs)}


@app.post("/api/scan")
def scan(req: ScanReq):
    try:
        snap = net.fetch_snap(req.url, use_tor=req.use_tor)
    except Exception as e:
        raise HTTPException(400, f"fetch failed: {e}")
    fp = detect.fingerprint(snap)
    sid = db.upsert_site(req.url, title=req.url, server=fp["server"],
                         favicon_hash=fp["favicon_hash"], content_hash=fp["content_hash"],
                         category="scanned", status=str(getattr(snap, "status", "?")))
    det = {k: v for k, v in detect.fingerprint(snap).items() if v}
    findings, fp2 = detect.scan(snap)
    rows = detect.pipeline_findings(sid, db, findings, fp2)
    return {"site_id": sid, "fingerprint": {k: v for k, v in fp.items() if v}, "findings": rows}


def _collect_job(job_id, source, want_tor):
    COLLECT_JOBS[job_id]["status"] = "collecting"
    try:
        from urllib.parse import urlparse

        import time as _t

        if want_tor:
            use_tor = active_proxy() is not None  # may bootstrap bundled Tor (waits up to 90s)
        else:
            use_tor = False
        COLLECT_JOBS[job_id]["use_tor"] = use_tor
        try:
            items = seeds.collect_source(source)
            db.log_source_health(source, ok=True)
        except Exception as e:
            db.log_source_health(source, ok=False, detail=str(e))
            raise
        new_urls = []
        for it in items:
            url = it["url"]
            if not url or db.site_id(url):
                continue
            db.upsert_site(url, title=it.get("title", "")[:200], category=it.get("category", "seed"))
            new_urls.append(url)
            if len(new_urls) >= (COLLECT_JOBS[job_id].get("cap") or 30):
                break
        if not use_tor:
            new_urls = [u for u in new_urls if ".onion" not in (urlparse(u).hostname or "")]
        COLLECT_JOBS[job_id]["sites_collected"] = len(new_urls)
        for i, url in enumerate(new_urls, 1):
            if COLLECT_JOBS[job_id].get("cancel"):
                break
            r = crawl_and_ingest(db, url, use_tor=use_tor)
            COLLECT_JOBS[job_id]["crawled"].append({"url": url, **r})
            COLLECT_JOBS[job_id]["progress"] = {"done": i, "total": len(new_urls)}
            _t.sleep(1.0)
        prof, pairs, per = stylo.match_all(db)
        COLLECT_JOBS[job_id]["merge"] = link.rebuild_actors(db, stylo_pairs=pairs)
        COLLECT_JOBS[job_id]["status"] = "done"
    except Exception as e:
        COLLECT_JOBS[job_id]["status"] = "error"
        COLLECT_JOBS[job_id]["error"] = str(e)


@app.post("/api/collect")
def collect(req: CollectReq, background: BackgroundTasks):
    want_tor = req.use_tor if req.use_tor is not None else True  # auto: try Tor, fall back to clearnet
    job_id = uuid.uuid4().hex[:12]
    COLLECT_JOBS[job_id] = {"status": "queued", "source": req.source, "use_tor": want_tor,
                            "sites_collected": 0, "crawled": [], "progress": None,
                            "merge": None, "error": None}
    background.add_task(_collect_job, job_id, req.source, want_tor)
    return {"job_id": job_id, "status": "queued", "source": req.source, "use_tor": want_tor,
            "message": f"Collection started in background (job {job_id}); "
                       f"poll /api/collect/status/{job_id} for progress"}


@app.get("/api/collect/status/{job_id}")
def collect_status(job_id: str):
    job = COLLECT_JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "collect job not found")
    return {**job, "id": job_id}


@app.get("/api/export")
def api_export(fmt: str = "json", q: str = "", kind: str = "all", title: str = "DarkForce report"):
    res = db.search(q, kind)
    out = []
    out += res["actors"]
    out += res["identifiers"]
    out += res["sites"]
    if not q and not out:
        out += [dict(r) for r in db.q("SELECT * FROM actors")]
        out += [dict(r) for r in db.q("SELECT * FROM identifiers")]
        out += [dict(r) for r in db.q("SELECT i.kind, i.value, s.url site_url, f.kind finding_kind, "
                                      "f.severity, f.detail FROM findings f JOIN sites s ON s.id=f.site_id "
                                      "LEFT JOIN identifiers i ON 1=0")]
    data, ct, fn = export_resp(out, fmt, title)
    return Response(content=data, media_type=ct,
                    headers={"Content-Disposition": f"attachment; filename={fn}"})


@app.get("/api/findings/{site_id}")
def site_findings(site_id: int):
    return db.findings_for_site(site_id)


class WatchReq(BaseModel):
    name: str
    pattern: str
    kind: str = "all"


@app.get("/api/watchlist")
def watchlist_list():
    return db.list_watchlists()


@app.post("/api/watchlist")
def watchlist_add(req: WatchReq):
    db.add_watchlist(req.name, req.pattern, req.kind)
    return {"added": req.name}


@app.delete("/api/watchlist/{wid}")
def watchlist_del(wid: int):
    db.delete_watchlist(wid)
    return {"deleted": wid}


@app.get("/api/alerts")
def alerts(limit: int = 100):
    return db.alerts(limit)


def event_stream():
    import asyncio
    import time

    try:
        yield ": connected\n\n"
        last = db.latest_alert_id()
        while True:
            fresh = db.alerts_since(last)
            for a in fresh:
                last = max(last, a["id"])
                yield f"data: {json.dumps(a)}\n\n"
            time.sleep(2)
    except asyncio.CancelledError:
        raise
    except GeneratorExit:
        return


@app.get("/api/alerts/stream")
def alerts_stream():
    from fastapi.responses import StreamingResponse

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/health/collectors")
def collector_health():
    return db.collector_health()


app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")


def main():
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))