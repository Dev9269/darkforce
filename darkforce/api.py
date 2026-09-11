import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import detect, link, net, seeds, stylo
from .db import DB
from .export import export as export_resp

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

db = DB()
app = FastAPI(title="DarkForce - Dark Web Threat Actor De-anonymization")


class SearchReq(BaseModel):
    q: str = ""
    kind: str = "all"


class ScanReq(BaseModel):
    url: str
    use_tor: bool = False


class CollectReq(BaseModel):
    source: str = "directory"


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


@app.post("/api/collect")
def collect(req: CollectReq):
    items = seeds.collect_source(req.source)
    n = 0
    for it in items:
        url = it["url"]
        if not url or db.site_id(url):
            continue
        db.upsert_site(url, title=it.get("title", "")[:200], category=it.get("category", "seed"))
        n += 1
    return {"source": req.source, "collected": n}


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


app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")


def main():
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))