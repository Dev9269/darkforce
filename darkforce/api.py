import datetime
import json
import os
import uuid
from typing import Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from . import auth, clearnet_index, detect, image_index, intel, link, net, seeds, stylo
from .collect import crawl_and_ingest
from .config import (ADMIN_PASSWORD, ADMIN_USER, announce_admin_password,
                     tor_available)
from .db import DB
from .export import export as export_resp
from .tor import active_proxy

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "web")

limiter = Limiter(key_func=get_remote_address)
db = DB()
app = FastAPI(title="DarkForce - Dark Web Threat Actor De-anonymization")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

COLLECT_JOBS = {}


def _max_stylo_confidence(database) -> float:
    """Highest attribution confidence the stylometry evidence actually supports.

    Only *significant* pairs count. Reporting the best raw score regardless of
    significance is how a coincidence ends up displayed as a finding.
    """
    try:
        _, pairs, _ = stylo.match_all(database)
    except Exception:
        return 0.0
    sig = [r for r in pairs if r.get("significant")]
    if not sig:
        return 0.0
    best = max(float(r.get("score") or 0.0) for r in sig)
    return round(min(best, link.STYLO_MAX), 2)


# Armed once at import from the process environment, which run.py sets only when
# --enable-probe is passed. Read at import (not per request) so probing cannot
# be switched on by anything that can write to the environment of a running
# server.
PROBE_ARMED = os.environ.get("DARKFORCE_ENABLE_PROBE") == "1"


def _seed_admin():
    """Create the initial admin the first time the app runs (config-seeded)."""
    try:
        created = db.ensure_admin(ADMIN_USER, auth.hash_password(ADMIN_PASSWORD))
    except Exception:
        return  # both backends tolerate (e.g. already-seeded race)
    # Only disclose a generated password when the account was really created.
    # Announcing it against a database that already has users would print a
    # credential that does not work, which trains the operator to ignore it.
    if created:
        announce_admin_password()


_seed_admin()


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    """Log every API call: user, role, method, path, status, timestamp."""
    if not request.url.path.startswith("/api/"):
        return await call_next(request)
    response = await call_next(request)
    try:
        who = auth.try_username(request.headers.get("authorization", ""))
        db.log_audit(who, "-" if who == "-" else "?", request.method,
                     request.url.path, response.status_code)
    except Exception:
        pass
    return response


class LoginReq(BaseModel):
    username: str
    password: str


class SearchReq(BaseModel):
    q: str = ""
    kind: str = "all"


class ScanReq(BaseModel):
    url: str
    use_tor: bool = False


class CollectReq(BaseModel):
    source: str = "directory"
    use_tor: Optional[bool] = None


class TrustReq(BaseModel):
    source: str
    trust: float = 0.5
    notes: str = ""


class AttrReq(BaseModel):
    subject_type: str = "link"
    subject: str
    claim: str = ""
    statement: str = "asserts"
    confidence: float = 0.5
    note: str = ""


class StealerImportReq(BaseModel):
    source: str = Field(default="stealer_log", max_length=200)
    text: str = Field(default="", max_length=2_000_000)


class CaseCreateReq(BaseModel):
    name: str
    status: str = "open"
    owner: str = "analyst"
    notes: str = ""


class CaseStatusReq(BaseModel):
    status: str


class CaseMemberReq(BaseModel):
    object_type: str = "site"
    object_id: int
    label: str = ""
    note: str = ""
    tag: str = ""


class EnrichReq(BaseModel):
    """One enrichment target. Deliberately a single value with no batch field:
    these call metered third-party APIs, and a bulk endpoint would turn one
    analyst click into a quota-burning sweep of someone else's free tier."""

    source: str
    value: str = ""


class ProbeReq(BaseModel):
    """An explicit target list. `url` is accepted as a convenience for a single
    host, but there is deliberately no field for a range, a depth or a
    follow-links switch."""

    urls: list[str] = Field(default_factory=list)
    url: str = ""
    allow_private: bool = False


@app.post("/api/login")
@limiter.limit("10/minute")
def login(request: Request, req: LoginReq):
    u = db.get_user(req.username)
    if not u or not auth.verify_password(req.password, u["password_hash"]):
        raise HTTPException(401, "invalid username or password")
    role = u["role"]
    return {"token": auth.issue_token(req.username, role), "username": req.username, "role": role}


@app.get("/api/me")
def me(who: dict = Depends(auth.current_user)):
    return who


@app.get("/api/audit")
def audit_endpoint(limit: int = 200, who: dict = Depends(auth.require_role("admin"))):
    return db.audit_logs(limit)


@app.get("/api/users")
def users_endpoint(who: dict = Depends(auth.require_role("admin"))):
    return db.list_users()


class UserReq(BaseModel):
    username: str
    password: str
    role: str = "analyst"


@app.post("/api/users")
def user_add(req: UserReq, who: dict = Depends(auth.require_role("admin"))):
    if req.role not in ("viewer", "analyst", "admin"):
        raise HTTPException(400, "role must be viewer|analyst|admin")
    if db.get_user(req.username):
        raise HTTPException(409, "user exists")
    db.add_user(req.username, auth.hash_password(req.password), req.role)
    db.log_audit(who["username"], "admin", "POST", "/api/users", 200)
    return {"added": req.username, "role": req.role}


@app.delete("/api/users/{uid}")
def user_del(uid: int, who: dict = Depends(auth.require_role("admin"))):
    db.delete_user(uid)
    return {"deleted": uid}


@app.get("/api/stats")
def stats():
    return db.stats()


@app.get("/api/search")
def search(q: str = "", kind: str = "all", category: str = "", start: str = "", end: str = ""):
    if not (q or "").strip():
        return []
    return db.search(q, kind, category=category or None, start=start or None, end=end or None)


@app.get("/api/identifiers")
def identifiers():
    return db.all_identifiers()


@app.get("/api/evidence/{objtype}/{objid}")
def evidence(objtype: str, objid: int, who: dict = Depends(auth.require_role("viewer"))):
    """Walk an identifier/finding/link/site/actor back to its observed raw
    fragment, the rated source, and any analyst statements on it."""
    return db.evidence_chain(objtype, objid)


@app.get("/api/sites/{sid}/snapshots")
def site_snapshots(sid: int, full: bool = False, body: bool = False,
                   who: dict = Depends(auth.require_role("viewer"))):
    """Retained responses for a site, newest first.

    `full` includes the stored body for every version, which is what an analyst
    needs to diff a page across time. `body` returns only the newest body, for
    the common "show me the current page" case - returning every version's body
    by default would be a large response for no reason.
    """
    site = db.one("SELECT s.*, src.name source_name FROM sites s "
                  "LEFT JOIN sources src ON src.id=s.source_id WHERE s.id=?", (sid,))
    if not site:
        raise HTTPException(404, "no such site")
    out = {"site": site, "history": db.snapshot_history(sid, limit=50)}
    if body:
        out["current"] = db.latest_snapshot(sid, with_html=True)
    if full:
        out["history"] = db.snapshot_history(sid, limit=50, with_html=True)
    out["integrity"] = db.verify_snapshot(sid)
    return out


@app.post("/api/probe")
def probe(req: ProbeReq, who: dict = Depends(auth.require_role("analyst"))):
    """Opt-in read-only GET against an explicit list of analyst-supplied URLs.

    Off unless this deployment was started with DARKFORCE_ENABLE_PROBE=1 at
    process start, which run.py does only when --enable-probe is passed. The
    flag is read once into a module constant so a mid-session change cannot
    turn it on, and each call still takes an explicit URL list - probing never
    enumerates or follows anything on its own.
    """
    from darkforce import probe as probe_mod

    if not PROBE_ARMED:
        return {"probing_enabled": False,
                "reason": "this deployment has not enabled probing; restart with --enable-probe"}
    urls = list(req.urls or []) + ([req.url] if req.url else [])
    prober = probe_mod.Prober(db, enabled=True,
                              allow_private=getattr(req, "allow_private", False) is True)
    return prober.probe_many(urls, analyst=who.get("username", "analyst"))


@app.get("/api/probe/status")
def probe_status(who: dict = Depends(auth.require_role("viewer"))):
    """Report probing posture without sending anything."""
    from darkforce import probe as probe_mod

    return {"enabled": PROBE_ARMED, "method": probe_mod.METHOD,
            "max_requests_per_call": probe_mod.MAX_REQUESTS,
            "min_host_interval_s": probe_mod.MIN_HOST_INTERVAL,
            "analyst_triggered_only": True, "autonomous": False}


@app.get("/api/clearnet/pivots")
def clearnet_pivots(limit: int = 100, include_ips: bool = True,
                    who: dict = Depends(auth.require_role("viewer"))):
    """Clearnet hosts this corpus points at, ranked.

    Read-only: mines stored post bodies and site rows, fetches nothing.
    `advertised_sites` is the count that matters for attribution - it is how
    many distinct darknet pages link the host. `seed_sites` is distribution
    infrastructure breadth, a different signal.
    """
    from darkforce.clearnet_index import mine_clearnet_hosts, pivot_hosts

    return {"mined": mine_clearnet_hosts(db, limit=max(1, min(limit, 1000))),
            "recommended": pivot_hosts(db, limit=max(1, min(limit, 200)),
                                       include_ips=include_ips)}


@app.get("/api/provenance/gap")
def provenance_gap(who: dict = Depends(auth.require_role("viewer"))):
    """Sites with no recorded collector.

    Left visible rather than backfilled with an invented source: the honest
    answer is that these predate provenance tracking, and a fabricated value
    would make an untraceable finding look traceable.
    """
    return db.provenance_gap()


@app.get("/api/sources/trust")
def trusts(who: dict = Depends(auth.require_role("viewer"))):
    return db.source_trusts()


@app.put("/api/sources/trust")
def trust_put(req: TrustReq, who: dict = Depends(auth.require_role("analyst"))):
    db.log_audit(who["username"], "analyst", "PUT", "/api/sources/trust", 200)
    return db.set_source_trust(req.source, req.trust, req.notes, analyst=who["username"])


@app.get("/api/attribution")
def attribution_list(subject_type: str = "", subject: str = "",
                     who: dict = Depends(auth.require_role("viewer"))):
    return db.list_attribution(subject_type, subject)


@app.post("/api/attribution")
def attribution_add(req: AttrReq, who: dict = Depends(auth.require_role("analyst"))):
    db.log_audit(who["username"], "analyst", "POST", "/api/attribution", 200)
    try:
        return db.add_attribution(req.subject_type, req.subject, req.claim, req.statement,
                                  req.confidence, req.note, analyst=who["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/wallets")
def wallets_all(q: str = "", kind: str = "", page: int = 1, per_page: int = 50):
    rows, total = db.list_wallets(q, kind, page, per_page)
    return {"items": rows, "total": total, "page": page, "per_page": per_page}


@app.get("/api/wallets/{address}")
def wallet_show(address: str):
    detail = db.wallet_detail(address)
    if not detail:
        raise HTTPException(404, "wallets not found")
    return detail


@app.get("/api/clusters/{address}")
def clusters_show(address: str):
    return db.wallet_cluster(address)


@app.get("/api/pivots")
def pivots(value: str = ""):
    return db.breach_pivots(value or None)


@app.get("/api/breaches")
def breaches_all(q: str = ""):
    return db.list_breaches(q)


@app.post("/api/import/stealer")
def stealer_import(req: StealerImportReq, who: dict = Depends(auth.require_role("analyst"))):
    from .collect import import_stealer_log
    db.log_audit(who["username"], "analyst", "POST", "/api/import/stealer", 200)
    try:
        out = import_stealer_log(db, req.text.splitlines(), req.source)
    except Exception as e:
        raise HTTPException(400, f"stealer import failed: {e}")
    return out


@app.post("/api/import/hibp")
def hibp_import(who: dict = Depends(auth.require_role("analyst"))):
    db.log_audit(who["username"], "analyst", "POST", "/api/import/hibp", 200)
    found = seeds.collect_hibp()
    n = 0
    for b in found:
        db.upsert_breach(b["name"], "hibp", primary_entity=b["email"], source_url="hibp")
        n += 1
    return {"imported": n, "examples": found[:10]}


@app.get("/api/cases")
def cases_all(status: str = ""):
    return db.list_cases(status or None)


@app.post("/api/cases")
def cases_create(req: CaseCreateReq, who: dict = Depends(auth.require_role("analyst"))):
    cid = db.create_case(req.name, req.status, req.owner, req.notes)
    if not cid:
        raise HTTPException(409, "case name already exists")
    db.log_audit(who["username"], "analyst", "POST", "/api/cases", 200)
    return {"id": cid, "name": req.name, "status": req.status}


@app.get("/api/cases/{cid}")
def cases_show(cid: int):
    c = db.get_case(cid)
    if not c:
        raise HTTPException(404, "case not found")
    return c


@app.patch("/api/cases/{cid}")
def cases_status(cid: int, req: CaseStatusReq, who: dict = Depends(auth.require_role("analyst"))):
    db.update_case_status(cid, req.status)
    db.log_audit(who["username"], "analyst", "PATCH", f"/api/cases/{cid}", 200)
    return {"id": cid, "status": req.status}


@app.post("/api/cases/{cid}/members")
def cases_member_add(cid: int, req: CaseMemberReq, who: dict = Depends(auth.require_role("analyst"))):
    if not db.get_case(cid):
        raise HTTPException(404, "case not found")
    db.case_add_member(cid, req.object_type, req.object_id, req.label, req.note, req.tag,
                       analyst=who["username"])
    db.log_audit(who["username"], "analyst", "POST", f"/api/cases/{cid}/members", 200)
    return {"case_id": cid, "object_type": req.object_type, "object_id": req.object_id}


@app.delete("/api/cases/{cid}/members/{mid}")
def cases_member_del(cid: int, mid: int, who: dict = Depends(auth.require_role("analyst"))):
    db.case_remove_member(cid, mid)
    return {"deleted": mid}


@app.get("/api/cases/{cid}/bundle")
def case_bundle(cid: int, fmt: str = "json", who: dict = Depends(auth.require_role("viewer"))):
    """Export a case bundle with chain-of-custody manifest (JSON/PDF).

    Bundle includes: case header, all members with evidence chains,
    HMAC-SHA256 manifest of all content hashes for integrity verification.
    """
    import hmac as _hmac
    import hashlib as _hashlib
    from .config import SECRET_KEY

    case = db.get_case(cid)
    if not case:
        raise HTTPException(404, "case not found")

    members = db.case_members(cid)
    bundle = {
        "case": case,
        "members": [],
        "manifest": {
            "created_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "case_id": cid,
            "items": [],
        },
    }

    for m in members:
        # Build evidence chain for this member
        chain = db.evidence_chain(m["object_type"], m["object_id"])
        content_hashes = []
        if chain:
            if chain.object and chain.object.get("content_hash"):
                content_hashes.append(chain.object["content_hash"])
            for obs in chain.observations or []:
                if obs.get("content_hash"):
                    content_hashes.append(obs["content_hash"])
            for attr in chain.attribution or []:
                pass  # attributions don't have content_hash

        member_bundle = {
            "member": m,
            "evidence_chain": chain,
            "content_hashes": content_hashes,
        }
        bundle["members"].append(member_bundle)
        for ch in content_hashes:
            bundle["manifest"]["items"].append({
                "member_id": m["id"],
                "content_hash": ch,
            })

    # HMAC manifest
    manifest_json = json.dumps(bundle["manifest"], sort_keys=True)
    manifest_hmac = _hmac.new(SECRET_KEY.encode(), manifest_json.encode(), _hashlib.sha256).hexdigest()
    bundle["manifest"]["hmac_sha256"] = manifest_hmac

    if fmt == "pdf":
        # Render a compact PDF of the case bundle
        from .export import report_pdf
        meta = {
            "title": f"Case #{cid}: {case['name']} - Chain of Custody Bundle",
            "subtitle": f"Case folder export with evidence chains and HMAC manifest",
            "classification": "UNCLASSIFIED // PUBLIC RELEASE",
            "date": datetime.date.today().isoformat(),
            "backend": "sqlite",
            "coverage": f"{len(members)} member(s), {sum(len(m['content_hashes']) for m in bundle['members'])} content hash(es)",
            "verdict": {
                "confidence": 1.0,
                "basis": "Chain-of-custody HMAC manifest",
                "rationale": f"Manifest HMAC-SHA256: {manifest_hmac[:32]}...",
            },
            "method_notes": [
                "Each evidence chain links back to its raw observation and source.",
                f"Manifest HMAC-SHA256 keyed by SECRET_KEY validates integrity: {manifest_hmac}",
            ],
        }
        records = []
        for m in bundle["members"]:
            if m["evidence_chain"] and m["evidence_chain"].object:
                records.append(m["evidence_chain"].object)
            for obs in m["evidence_chain"].observations or []:
                records.append({"type": "observation", **obs})
            for attr in m["evidence_chain"].attribution or []:
                records.append({"type": "attribution", **attr})
        from .export import report_pdf
        data = report_pdf(meta, records=records[:60])
        return Response(content=data, media_type="application/pdf",
                        headers={"Content-Disposition": f"attachment; filename=case_{cid}_bundle.pdf"})

    # JSON bundle
    return Response(
        content=json.dumps(bundle, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=case_{cid}_bundle.json"},
    )


@app.post("/api/ops/detect")
def ops_detect(who: dict = Depends(auth.require_role("analyst"))):
    """Run operational detection: gone-dark sites + successor-propaganda scan."""
    db.log_audit(who["username"], "analyst", "POST", "/api/ops/detect", 200)
    return db.detect_ops(days=14)


@app.get("/api/actors")
def actors_all():
    return db.all_actors()


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
def graph(actor_id: int = 0, min_conf: float = 0.0):
    g = db.graph(actor_id or None, min_conf=min_conf)
    _annotate_graph_safety(g)
    return g


def _site_safety(site):
    """Classify a DB site row into a safety record.

    site: dict with keys id, url, title, category.
    Returns dict (site_id, url, title, category, safety, threat_types,
    severity_counts, findings_count).
    """
    site_id = site["id"]
    url = site["url"] or ""
    title = site["title"] or ""
    category = site["category"] or "unknown"

    findings = db.findings_for_site(site_id)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    threat_types = set()

    for f in findings:
        sev = (f.get("severity") or "").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        kind = (f.get("kind") or "").lower()
        detail = (f.get("detail") or "").lower()
        evidence = (f.get("evidence") or "").lower()
        text = f"{kind} {detail} {evidence}"

        if any(k in text for k in ["ransomware", "ransom", "encrypt", "decrypt"]):
            threat_types.add("ransomware")
        if any(k in text for k in ["malware", "trojan", "virus", "backdoor", "rat", "stealer", "botnet", "c2", "command and control"]):
            threat_types.add("malware")
        if any(k in text for k in ["phishing", "credential harvest", "fake login", "spoof"]):
            threat_types.add("phishing")
        if any(k in text for k in ["exploit", "vulnerability", "rce", "injection", "xss", "sqli"]):
            threat_types.add("exploit")

    if "ransomware" in threat_types:
        safety = "ransomware"
    elif "malware" in threat_types:
        safety = "malware"
    elif "phishing" in threat_types:
        safety = "phishing"
    elif severity_counts["critical"] > 0 or severity_counts["high"] > 2:
        safety = "malicious"
    elif severity_counts["high"] > 0 or severity_counts["medium"] > 3:
        safety = "suspicious"
    elif severity_counts["medium"] > 0 or severity_counts["low"] > 5:
        safety = "suspicious"
    else:
        cat = (category or "").lower()
        if cat in ["ransomware", "malware", "hitman", "fraud/scam", "counterfeit", "weapons", "leaked data"]:
            safety = "suspicious"
        elif cat in ["news", "directories", "forums", "resources", "free", "privacy/hosting"]:
            safety = "safe"
        else:
            safety = "unknown"

    return {
        "site_id": site_id,
        "url": url,
        "title": title,
        "category": category,
        "safety": safety,
        "threat_types": list(threat_types),
        "severity_counts": severity_counts,
        "findings_count": len(findings),
    }


def _annotate_graph_safety(g, min_prefix=12):
    """Attach safety info to site/onion nodes in a graph payload.

    db.graph truncates node labels (26 chars) and ids (18 chars), so match
    sites by exact URL first, then by shared prefix.
    """
    try:
        site_rows = db.q("SELECT id, url, title, category FROM sites")
        site_rows = [dict(r) for r in site_rows]
        by_url = {s["url"]: s for s in site_rows}
        urls = [s["url"] for s in site_rows]

        for n in g.get("nodes", []):
            if n.get("kind") not in ("site", "onion"):
                continue
            label = (n.get("label") or "").strip()
            nid = n.get("id") or ""
            nid = nid.replace("site:", "", 1).replace("onion:", "", 1)

            site_row = by_url.get(label) or by_url.get(nid)
            if site_row is None:
                for u in urls:
                    if len(label) >= min_prefix and u.startswith(label):
                        site_row = by_url[u]
                        break
            if site_row is None and len(nid) >= min_prefix:
                for u in urls:
                    if u.startswith(nid):
                        site_row = by_url[u]
                        break
            if site_row is None:
                n.setdefault("safety", "unknown")
                n.setdefault("category", "unknown")
                continue
            n["safety"] = _site_safety(site_row)["safety"]
            n["category"] = site_row.get("category") or "unknown"
    except Exception as e:
        print(f"Error annotating graph safety: {e}")


@app.get("/api/sites/safety")
def sites_safety():
    """Get safety status for all sites (malicious/ransomware/malware/phishing/safe)."""
    try:
        results = {}
        for site in db.q("SELECT id, url, title, category FROM sites"):
            rec = _site_safety(site)
            results[str(rec["site_id"])] = rec
        return results
    except Exception as e:
        import traceback
        print(f"Error in sites_safety: {e}")
        traceback.print_exc()
        return {"error": str(e)}


@app.get("/api/network/analysis")
def network_analysis():
    from .graph_analysis import analyze_network

    return analyze_network(db)


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


# heuristic purpose tags for the site-inventory card. Ordered: first match wins.
PURPOSE_RULES = [
    ("hitman / for-hire", ("hitman", "contract kill", "assassination", "murder for hire", "kill order")),
    ("weapons / guns", ("glock", "beretta", "cz ", "ak-47", "ak47", "ar-15", "rifles", "pistol", "smg", "ammunition", "guns", "weapons", "firearm")),
    ("drugs", ("cocaine", "heroin", "mdma", "ecstasy", "meth", "lsd", "fentanyl", "weed", "cannabis", "marijuana", "xanax", "adderall", "dmt", "ketamine", "psychedel")),
    ("stolen data / dumps", ("dump", "cc ", " card ", "carding", "track", "pin", "bins", "leaked", "combo list", "database", "breach", "swipe")),
    ("fraud / money laundering", ("fraud", "launder", "crypto tumbl", "money mule", "paypal", "verification", "fake id", "passport", "identity")),
    ("hacking services", ("ddos", "ransomware", "malware", "exploit", "botnet", "hack", "crack", "spyware", "keylogger", "phishing", "zeroday", "0day")),
    ("mail spam / enclave", ("spam", "smtp", "sendgrid", "bulk mail", "mailer", "newsletter")),
    ("forums / discussion", ("forum", "thread", "post reply", "member", "rules", "profile", "signature")),
    ("marketplace", ("market", "shop", "store", "vendor", "escrow", "review", "buy", "sell", "listed")),
    ("news / media", ("news", "report", "headline", "press", "journalist", "article", "breaking")),
    ("search engine", ("search", "index", "crawler", "query")),
    ("directory / listings", ("directory", "verified", "list", "status", "uptime")),
]

DEFAULT_PURPOSE = "unknown / uncategorised"


def _site_purpose(row):
    text = (row.get("title") or "") + " " + (row.get("digest") or "") + " " + (row.get("category") or "")
    low = text.lower()
    for label, kws in PURPOSE_RULES:
        for k in kws:
            if k in low:
                return label
    return DEFAULT_PURPOSE


@app.get("/api/sites")
def sites_all(category: str = "", q: str = "", page: int = 0, per_page: int = 100):
    from darkforce.categories import normalize_category
    if category or (q or "").strip() or page or per_page != 100:
        cat = normalize_category(category) if category else None
        rows, total = db.sites_catalog(cat, q, page or 1, per_page)
        out = []
        for r in rows:
            r["category"] = normalize_category(r.get("category") or "other")
            r["purpose"] = _site_purpose(r)
            r.pop("digest", None)
            r.pop("content_hash", None)
            r.pop("raw", None)
            out.append(r)
        return {"items": out, "total": total, "page": page or 1, "per_page": per_page}
    out = []
    for r in db.sites_all():
        r["category"] = normalize_category(r.get("category") or "other")
        r["purpose"] = _site_purpose(r)
        r.pop("digest", None)
        out.append(r)
    return out


@app.get("/api/categories")
def categories_ref():
    """Canonical category taxonomy + live counts for the sites-register filter."""
    import collections

    from darkforce.categories import normalize_category, CANONICAL
    counts = collections.Counter()
    for r in db.q("SELECT category, COUNT(*) c FROM sites GROUP BY category"):
        counts[normalize_category(r["category"] or "other")] += r["c"]
    return {
        "categories": CANONICAL,
        "counts": {c: counts[c] for c in CANONICAL},
        "total": sum(counts.values()),
    }


RESOURCE_CATEGORIES = ("free", "resources", "hacking", "malware", "leaked data")


@app.get("/api/resources")
def resources_catalog(category: str = ""):
    """Free dark-web resource catalog (tool/crack/warez boards, malware,
    leak references) -- metadata only: address, title, category, status,
    last scan, headline. Filter by one canonical category via ?category=."""
    from darkforce.categories import normalize_category
    if category:
        cat = normalize_category(category)
        cats = (cat,) if cat in RESOURCE_CATEGORIES else RESOURCE_CATEGORIES
    else:
        cats = RESOURCE_CATEGORIES
    rows = db.q(
        "SELECT s.id, s.url, s.title, s.category, s.status, s.first_seen, s.last_scan, s.lang "
        "FROM sites s WHERE s.category IN (" + ",".join("?" * len(cats)) + ") "
        "  AND (s.title IS NULL OR s.title NOT LIKE 'URLhaus%') "
        "ORDER BY s.last_scan DESC, s.id DESC LIMIT 250",
        cats,
    )
    if rows:
        ids = [r["id"] for r in rows]
        posts = db.q(
            "SELECT p.site_id, p.title FROM posts p WHERE p.site_id IN (" + ",".join("?" * len(ids)) + ") "
            "ORDER BY COALESCE(p.ts, '') DESC, p.id DESC",
            ids,
        )
        seen = set()
        headline = {}
        for p in posts:
            if p["site_id"] not in seen:
                headline[p["site_id"]] = p["title"]
                seen.add(p["site_id"])
        out = []
        for r in rows:
            item = dict(r)
            item["category"] = normalize_category(r["category"] or "other")
            item["headline"] = headline.get(r["id"])
            out.append(item)
        return out
    return []


@app.get("/api/news")
def news_feed(limit: int = 60):
    """Darknet news feed: latest posts from news-category sites + status
    boards, newest first. Called by the Darknet News page which re-polls
    every 60s for real-time updates while the collector re-scans."""
    limit = max(1, min(limit, 250))
    rows = db.q(
        "SELECT p.id, p.handle, p.title, p.url, p.ts, s.id site_id, s.url site_url, "
        "       s.title site_title, s.status "
        "FROM posts p JOIN sites s ON s.id = p.site_id "
        "WHERE s.category = ? "
        "ORDER BY COALESCE(p.ts, s.last_scan) DESC, p.id DESC LIMIT ?",
        ("news", limit),
    )
    # fall back to post-title-level news classification when a news site is
    # still un-crawled but its posts exist under a provenance category
    extra = db.q(
        "SELECT p.id, p.handle, p.title, p.url, p.ts, s.id site_id, s.url site_url, "
        "       s.title site_title, s.status "
        "FROM posts p JOIN sites s ON s.id = p.site_id "
        "WHERE s.category NOT IN ('news') AND (lower(p.title) LIKE '%news%' "
        "   OR lower(p.title) LIKE '%breaking%' OR lower(p.title) LIKE '%coverage%') "
        "ORDER BY COALESCE(p.ts, s.last_scan) DESC, p.id DESC LIMIT ?",
        (limit,),
    )
    merged = {p["id"]: dict(p) for p in [*rows, *extra]}
    return sorted(merged.values(), key=lambda p: p.get("ts") or "", reverse=True)[:limit]


@app.get("/api/stylo/{handle}")
def stylo_for(handle: str):
    return stylo.match_handle(db, handle)


@app.get("/api/stylo")
def stylo_all():
    return stylo.match_all(db)[2]


@app.get("/api/timeline")
def timeline(start: str = "", end: str = ""):
    if not (start or "").strip() and not (end or "").strip():
        return []
    evs = [dict(r) for r in db.q("SELECT ts, handle, title, url, 'post' etype FROM posts"
                                 " WHERE (?='' OR ts>=?) AND (?='' OR ts<=?)", (start, start, end, end))]
    evs += [dict(r) for r in db.q("SELECT first_seen ts, detail title, url, 'finding' etype FROM findings"
                                  " WHERE (?='' OR first_seen>=?) AND (?='' OR first_seen<=?)", (start, start, end, end))]
    evs.sort(key=lambda e: e["ts"] or "", reverse=True)
    return evs


@app.post("/api/refresh")
def  refresh(who: dict = Depends(auth.require_role("analyst"))):
    prof, pairs, per = stylo.match_all(db)
    res = link.rebuild_actors(db, stylo_pairs=pairs)
    return {**res, "stylo_pairs": len(pairs)}


@app.post("/api/scan")
def  scan(req: ScanReq, who: dict = Depends(auth.require_role("analyst"))):
    try:
        snap = net.fetch_snap(req.url, use_tor=req.use_tor)
    except Exception as e:
        raise HTTPException(400, f"fetch failed: {e}")
    fp = detect.fingerprint(snap)
    sid = db.upsert_site(req.url, title=req.url, server=fp["server"],
                         favicon_hash=fp["favicon_hash"], content_hash=fp["content_hash"],
                         category="scanned", status=str(getattr(snap, "status", "?")),
                         cert_sans=fp["cert_sans"] or None,
                         tls_issuer=fp["tls_issuer"] or None,
                         cert_fp=fp["cert_fp"] or None)
    det = {k: v for k, v in detect.fingerprint(snap).items() if v}
    findings, fp2 = detect.scan(snap, clearnet_index.load(db))
    src = db.one("SELECT source_id FROM sites WHERE id=?", (sid,))
    source_id = src["source_id"] if src else None
    rows = detect.pipeline_findings(sid, db, findings, fp2, url=req.url,
                                    source_id=source_id, method="detect:scan")
    return {"site_id": sid, "fingerprint": {k: v for k, v in fp.items() if v}, "findings": rows}


@app.get("/api/infra/correlations")
def infra_correlations(limit: int = 200, who: dict = Depends(auth.require_role("analyst"))):
    """Per onion site, the clearnet hosts whose stored fingerprints it matches."""
    rows = db.q(
        "SELECT id,url,favicon_hash,content_hash,server FROM sites "
        "WHERE url LIKE '%.onion%' "
        "AND (favicon_hash IS NOT NULL OR content_hash IS NOT NULL "
        "     OR (server IS NOT NULL AND server <> '')) "
        "ORDER BY last_scan DESC LIMIT ?",
        (limit,))
    idx = clearnet_index.load(db)
    correlations = []
    for row in rows:
        r = dict(row)
        fp = {"favicon_hash": r.get("favicon_hash"),
              "content_hash": r.get("content_hash"),
              "server": r.get("server") or ""}
        matches = idx.lookup(fp)
        if not matches:
            continue
        correlations.append({
            "onion_url": r["url"],
            "site_id": r["id"],
            "candidates": [
                {"host": m["host"], "title": m["title"],
                 "attribute": m["attribute"], "confidence": m["confidence"]}
                for m in matches
            ],
        })
    return {"correlations": correlations}


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
            from darkforce.categories import normalize_category
            db.upsert_site(url, title=it.get("title", "")[:200],
                           category=normalize_category(it.get("category", "seed")))
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
def  collect(req: CollectReq, background: BackgroundTasks, who: dict = Depends(auth.require_role("analyst"))):
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
def api_export(fmt: str = "json", q: str = "", kind: str = "all",
               title: str = "Dark Force - threat actor report",
               who: dict = Depends(auth.require_role("viewer"))):
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

    if fmt == "pdf":
        from .config import DATABASE_URL
        st = db.stats()
        meta = {
            "title": title,
            "subtitle": "Dark web threat-actor de-anonymization - analyst summary",
            "classification": "UNCLASSIFIED // PUBLIC RELEASE",
            "backend": "postgres" if DATABASE_URL else "sqlite",
            "coverage": f"{st.get('actors', 0)} actors, {st.get('sites', 0)} sites, "
                        f"{st.get('identifiers', 0)} identifiers, {st.get('findings', 0)} findings",
            "verdict": {
                "confidence": _max_stylo_confidence(db),
                "basis": "stylometric n-gram overlap + shared identifiers",
                "rationale": (f"High-confidence persona linkage is flagged when a handle's n-gram "
                              f"profile is closer than 0.5 to another actor's corpus while sharing "
                              f"at least one unique identifier (PGP/wallet/email/onion)."),
            },
            "method_notes": [
                "Collection: read-only fetch of publicly served pages via clearnet discovery APIs "
                "(Ahmia, dark.fail, ransomware.live) and Tor-restricted crawling with per-host rate "
                "limiting and circuit rotation.",
                "Entity resolution: identifier overlap with weighted confidence edges; stylometry: "
                "character n-gram authorship profiles with cosine similarity and feature "
                "explainability (top contributing features shown per match).",
                "Attribution is analytic judgment with confidence, never confirmed identity.",
            ],
        }
        from .export import report_pdf
        data = report_pdf(meta, records=out[:60])
        return Response(content=data, media_type="application/pdf",
                        headers={"Content-Disposition": "attachment; filename=darkforce_report.pdf"})

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
def  watchlist_add(req: WatchReq, who: dict = Depends(auth.require_role("analyst"))):
    db.add_watchlist(req.name, req.pattern, req.kind)
    return {"added": req.name}


@app.delete("/api/watchlist/{wid}")
def  watchlist_del(wid: int, who: dict = Depends(auth.require_role("analyst"))):
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


@app.get("/api/digest")
def api_digest(hours: int = 24, fmt: str = "json",
               who: dict = Depends(auth.require_role("viewer"))):
    """Nightly / ad-hoc digest of recent activity. fmt = json|pdf|md."""
    from .export import digest_pdf, to_json

    activity = db.recent_activity(hours=hours)
    from .config import DATABASE_URL
    backend_name = "postgres" if DATABASE_URL else "sqlite"
    title = "DarkForce Nightly Digest"
    meta = {
        "title": title,
        "subtitle": "24-hour collection summary",
        "date": activity["generated_at"],
        "backend": backend_name,
    }
    if fmt == "pdf":
        pdf = digest_pdf(meta, activity)
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition": "attachment; filename=darkforce-digest.pdf"})
    if fmt == "md":
        lines = [
            f"# {title}",
            "",
            f"_Generated {activity['generated_at']} (UTC) - backend {backend_name}_",
            "",
            "## Snapshot",
            "",
            "| Statistic | 24h | Total |",
            "|---|---|---|",
            f"| Sites indexed | {activity['new_sites_total']} | {activity['snapshot'].get('sites', 0)} |",
            f"| Findings | {activity['new_findings_total']} | {activity['snapshot'].get('findings', 0)} |",
            f"| Actors | - | {activity['snapshot'].get('actors', 0)} |",
            f"| Identifiers | - | {activity['snapshot'].get('identifiers', 0)} |",
            f"| Alerts raised | {activity['new_alerts_total']} | - |",
            "",
            "## New sites by category",
            "",
        ]
        for cat, n in sorted(activity["new_sites_by_category"].items(), key=lambda kv: -kv[1]):
            lines.append(f"- {cat}: {n}")
        lines.append("")
        lines.append("## High / critical findings (24h)")
        lines.append("")
        for f in activity["high_critical_findings"][:50]:
            lines.append(f"- [{f['severity']}] {f.get('kind')} @ {f.get('site') or f.get('url')}")
        lines.append("")
        lines.append("## Fresh alerts (24h)")
        lines.append("")
        for a in activity["new_alerts"][:50]:
            lines.append(f"- [{a.get('kind')}] {a.get('title')}")
        return Response("\n".join(lines) + "\n", media_type="text/markdown")
    return activity


@app.get("/api/health/collectors")
def collector_health():
    return db.collector_health()


@app.get("/healthz")
def healthz():
    """Liveness probe for container platforms (Railway/Render/Fly/Spaces).

    Must not require auth and must not hit the network: orchestrators poll this
    on a schedule and treat failures as a crash.
    """
    try:
        db.one("SELECT 1")
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(503, f"database unavailable: {e}")


class SpaStaticFiles(StaticFiles):
    """StaticFiles with HTML5-history fallback: unknown non-API, non-asset
    paths get index.html so BrowserRouter deep links (/registry) resolve."""

    async def get_response(self, path: str, scope):
        from starlette.exceptions import HTTPException as StarletteHTTPException
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as e:
            if e.status_code != 404 or path.startswith("/api/"):
                raise
            index = os.path.join(WEB_DIR, "index.html")
            if os.path.exists(index):
                return FileResponse(index)
            raise


@app.get("/api/intel/available")
def intel_available(who: dict = Depends(auth.require_role("viewer"))):
    """Which enrichment collectors are configured. A missing key is normal, so the
    UI needs to be able to distinguish 'not configured' from 'broken'."""
    return {"available": intel.available(),
            "collectors": {k: {"requires": v["requires"], "input": v["input"]}
                           for k, v in intel.COLLECTORS.items()}}


@app.post("/api/intel/enrich")
def intel_enrich(req: EnrichReq, who: dict = Depends(auth.require_role("analyst"))):
    """Look up one value in one collector. Returns the raw result with its
    provenance and confidence, or a clear 'not configured' rather than an empty
    success that reads as a clean bill of health."""
    if req.source not in intel.COLLECTORS:
        raise HTTPException(400, f"unknown collector: {req.source}")
    if not req.value.strip():
        raise HTTPException(400, "value is required")
    if not intel.available().get(req.source):
        raise HTTPException(503, f"{req.source} is not configured "
                                 f"(set {intel.COLLECTORS[req.source]['requires']})")
    result = intel.collect(req.source, req.value.strip())
    if result is None:
        return {"source": req.source, "value": req.value.strip(), "result": None,
                "note": "no result; for a reputation source that means no adverse "
                        "history, which is not evidence of innocence"}
    return {"source": req.source, "value": req.value.strip(), "result": result,
            "enriched_by": who["username"]}


@app.get("/api/images/stats")
def images_stats(who: dict = Depends(auth.require_role("viewer"))):
    return {"stored": db.image_hash_stats(),
            "ubiquity_limit": image_index.UBIQUITY_LIMIT,
            "thresholds": image_index.ImageIndex.THRESHOLDS}


@app.get("/api/images/avatars")
def images_avatars(actor_id: Optional[int] = None,
                   who: dict = Depends(auth.require_role("viewer"))):
    """Stored avatar hashes, optionally for one actor, each annotated with how
    many actors share it. An avatar on more than the ubiquity limit is a default
    image, and the count is returned so nobody mistakes it for an identifier."""
    rows = db.image_hashes(kind="avatar", actor_id=actor_id)
    for r in rows:
        u = db.image_ubiquity("avatar", r["phash"])
        r["shared_by_actors"] = u["actors"] or len(u["handles"])
        r["is_default_image"] = r["shared_by_actors"] > image_index.UBIQUITY_LIMIT
    return {"ubiquity_limit": image_index.UBIQUITY_LIMIT, "avatars": rows}


app.mount("/", SpaStaticFiles(directory=WEB_DIR, html=True), name="web")


def main():
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
