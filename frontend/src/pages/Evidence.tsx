import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { AlertTriangle, ArrowLeft, CircleHelp, Fingerprint, Link2, LoaderCircle, Scale, Search, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  addAttribution, errorText, getAttribution, getEvidenceChain, getSourceTrusts, getText, setSourceTrust,
  type Attribution, type EvidenceChain, type TrustRow,
} from "@/lib/darkforce";

const OBJTYPES = ["identifier", "finding", "link", "site", "actor"] as const;

function TrustEditor({ row }: { row: TrustRow }) {
  const queryClient = useQueryClient();
  const [trust, setTrust] = useState(row.trust ?? 0.5);
  const [notes, setNotes] = useState(row.notes ?? "");
  const mutation = useMutation({
    mutationFn: () => setSourceTrust(getText(row.source_name ?? row.source), trust, notes),
    onSuccess: () => {
      toast.success(`Trust rated for ${getText(row.source_name ?? row.source)}`);
      void queryClient.invalidateQueries({ queryKey: ["source-trusts"] });
    },
    onError: (error) => toast.error(`Trust update failed: ${errorText(error)}`),
  });
  return (
    <div className="source-item trust-editor" style={{ display: "grid", gap: "0.5rem", gridTemplateColumns: "1fr" }}>
      <div style={{ display: "flex", gap: "0.6rem", alignItems: "center" }}>
        <span className="source-index mono">{getText(row.source_type ?? "src")}</span>
        <span>{getText(row.source_name ?? row.source)}</span>
        <input
          type="range" min="0" max="1" step="0.05" value={trust}
          onChange={(event) => setTrust(Number(event.target.value))}
          aria-label={`Trust for ${getText(row.source_name ?? row.source)}`}
          style={{ flex: 1 }}
        />
        <span className="mono">{(trust * 100).toFixed(0)}%</span>
        <Button
          variant="outline" size="sm"
          disabled={mutation.isPending}
          onClick={() => mutation.mutate()}
          data-testid={`trust-save-${getText(row.source_name ?? row.source).toLowerCase()}`}
        >
          {mutation.isPending ? <LoaderCircle className="animate-spin" size={13} /> : <ShieldCheck size={13} />} Rate
        </Button>
      </div>
      <Input value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="Rating notes (optional)" />
      <span className="mono muted-text">{getText(row.rated_by, "unrated")} · {getText(row.rated_at, "")}</span>
    </div>
  );
}

function ChainView({ chain }: { chain?: EvidenceChain }) {
  if (!chain?.object) return <div className="query-state"><CircleHelp size={16} /> No object for this id — nothing observed.</div>;
  return (
    <div className="stat-detail-table-stack" data-testid="evidence-chain-view">
      <div className="panel-subtitle">
        Chain for {getText(chain.type, "object")} #{chain.id}
        {chain.trust != null ? <> · source trust <span className="mono">{(chain.trust * 100).toFixed(0)}%</span></> : null}
      </div>
      <details className="finding-item severity-medium" open>
        <summary><span className="severity-dot" /><span className="finding-title">STORED OBJECT</span></summary>
        <div className="evidence-text mono">{JSON.stringify(chain.object, null, 2)}</div>
        <div className="finding-source mono">CONTENT HASH / {getText(chain.object?.content_hash, "none")}</div>
      </details>
      {(chain.observations ?? []).map((obs, index) => (
        <details key={String(obs.content_hash ?? obs.id ?? index)} className="finding-item severity-low" open={index === 0}>
          <summary>
            <span className="severity-dot" />
            <span className="finding-title">{getText(obs.method, "observation")} / {getText(obs.kind, "kind")}</span>
            {obs.evidence ? <span className="mono muted-text">&nbsp;[{getText(obs.evidence).slice(0, 60)}]</span> : null}
          </summary>
          <div className="evidence-text mono">{getText(obs.raw, "(no raw fragment captured)")}</div>
          <div className="finding-source mono">
            HASH / {getText(obs.content_hash, "none")} · {getText(obs.source_name, "no source")} · {getText(obs.observed_at, "")}
          </div>
        </details>
      ))}
      {(chain.attribution ?? []).map((attr) => <AttributionRow key={attr.id} attr={attr} />)}
    </div>
  );
}

function AttributionRow({ attr }: { attr: Attribution }) {
  return (
    <div className="finding-item severity-low attribution-row" data-testid="attribution-row">
      <div className="finding-title">
        <Scale size={13} /> {getText(attr.statement, "asserts").toUpperCase()}
        <span className="mono muted-text">&nbsp;{getText(attr.subject, "—")}</span>
      </div>
      <div className="finding-detail">
        {getText(attr.claim, "no claim")}
        <div className="finding-source mono">
          CONF {(attr.confidence ?? 0).toFixed(2)} · {getText(attr.analyst, "analyst")} · {getText(attr.ts, "")}
          {getText(attr.note) ? ` · ${attr.note}` : ""}
        </div>
      </div>
    </div>
  );
}

export default function Evidence() {
  const queryClient = useQueryClient();
  const [objType, setObjType] = useState<string>("identifier");
  const [objId, setObjId] = useState("");
  const [lookup, setLookup] = useState<{ type: string; id: string } | null>(null);
  const [source, setSource] = useState("");
  const [catSubjectType, setCatSubjectType] = useState("link");
  const [catSubject, setCatSubject] = useState("");
  const [catClaim, setCatClaim] = useState("");
  const [catStatement, setCatStatement] = useState("asserts");
  const [catConfidence, setCatConfidence] = useState(0.5);
  const [catNote, setCatNote] = useState("");

  const trustsQuery = useQuery({ queryKey: ["source-trusts"], queryFn: getSourceTrusts, retry: false });
  const attributionQuery = useQuery({ queryKey: ["attribution"], queryFn: () => getAttribution(), retry: false });
  const chainQuery = useQuery({
    queryKey: ["evidence-chain", lookup?.type, lookup?.id],
    queryFn: () => getEvidenceChain(lookup!.type, lookup!.id),
    enabled: Boolean(lookup?.id),
    retry: false,
  });

  const rootMutation = useMutation({
    mutationFn: () => setSourceTrust(source.trim(), 0.7),
    onSuccess: () => {
      toast.success(`Trust seeded for ${source.trim()}`);
      setSource("");
      void queryClient.invalidateQueries({ queryKey: ["source-trusts"] });
    },
    onError: (error) => toast.error(`Trust failed: ${errorText(error)}`),
  });
  const attrMutation = useMutation({
    mutationFn: () =>
      addAttribution({
        subject_type: catSubjectType, subject: catSubject, claim: catClaim,
        statement: catStatement, confidence: catConfidence, note: catNote,
      }),
    onSuccess: () => {
      toast.success("Attribution statement recorded");
      setCatSubject(""); setCatClaim(""); setCatNote("");
      void queryClient.invalidateQueries({ queryKey: ["attribution"] });
    },
    onError: (error) => toast.error(`Attribution failed: ${errorText(error)}`),
  });

  const trusts = trustsQuery.data ?? [];
  const submitChain = (event: React.FormEvent) => {
    event.preventDefault();
    if (objId.trim()) setLookup({ type: objType, id: objId.trim() });
  };

  return (
    <div className="console-shell registry-shell" data-testid="evidence-page">
      <nav className="registry-nav">
        <Link to="/" className="registry-back"><ArrowLeft size={14} /> DARKFORCE CONSOLE</Link>
        <Link to="/analyst" className="registry-back" data-testid="evidence-analyst-link"><Fingerprint size={14} /> ANALYST</Link>
        <span className="registry-title"><Scale size={14} /> EVIDENCE LEDGER — PROVENANCE &amp; ATTRIBUTION</span>
        <span className="mono registry-total">{trusts.length} RATED SOURCE{(trusts.length === 1 ? "" : "S")}</span>
      </nav>
      <main className="console-main">
        <section className="console-panel" data-testid="trust-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker"><ShieldCheck size={14} /> SOURCE TRUST RATINGS</div>
              <div className="panel-subtitle">Rate a collector/source 0–1; the rating rides along every evidence chain it produced</div>
            </div>
            <div className="pipeline-buttons">
              <Input value={source} onChange={(event) => setSource(event.target.value)} placeholder="New source name…" aria-label="Source to rate" data-testid="trust-new-source-input" />
              <Button variant="outline" size="sm" disabled={!source.trim() || rootMutation.isPending} onClick={() => rootMutation.mutate()} data-testid="trust-root-button">
                {rootMutation.isPending ? <LoaderCircle className="animate-spin" size={13} /> : <ShieldCheck size={13} />} Seed 70%
              </Button>
            </div>
          </div>
          <div className="source-list">
            {trusts.map((row) => <TrustEditor key={getText(row.source_name ?? row.source)} row={row} />)}
            {!trusts.length && <div className="query-state"><CircleHelp size={16} /> No trust ratings yet.</div>}
          </div>
        </section>

        <section className="console-panel" data-testid="evidence-chain-lookup-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker"><Search size={14} /> EVIDENCE CHAIN LOOKUP</div>
              <div className="panel-subtitle">Walk an object back to its observed raw fragment, the rated source, and analyst statements</div>
            </div>
            <form onSubmit={submitChain} className="pipeline-buttons">
              <select value={objType} onChange={(event) => setObjType(event.target.value)} className="console-select" aria-label="Object type" data-testid="evidence-objtype-select">
                {OBJTYPES.map((type) => <option key={type} value={type}>{type.toUpperCase()}</option>)}
              </select>
              <Input value={objId} onChange={(event) => setObjId(event.target.value)} placeholder="Object id (e.g. 3)" aria-label="Object id" data-testid="evidence-objid-input" />
              <Button type="submit" disabled={!objId.trim() || chainQuery.isFetching} data-testid="evidence-lookup-button">
                {chainQuery.isFetching ? <LoaderCircle className="animate-spin" size={13} /> : <Link2 size={13} />} Trace
              </Button>
            </form>
          </div>
          {chainQuery.isLoading ? (
            <div className="query-state"><LoaderCircle className="animate-spin" size={16} /> Resolving chain…</div>
          ) : chainQuery.error ? (
            <div className="query-state query-error"><AlertTriangle size={16} /> {errorText(chainQuery.error)}</div>
          ) : lookup ? (
            <ChainView chain={chainQuery.data} />
          ) : (
            <div className="query-state"><CircleHelp size={16} /> Enter an object type and id to trace its provenance.</div>
          )}
        </section>

        <section className="console-panel" data-testid="attribution-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker"><Scale size={14} /> ANALYST ATTRIBUTION</div>
              <div className="panel-subtitle">Assert, deny or dispute a claim; statements are ledgered with the analyst + timestamp</div>
            </div>
            <form
              onSubmit={(event) => { event.preventDefault(); if (catSubject.trim()) attrMutation.mutate(); }}
              className="pipeline-buttons"
              style={{ flexWrap: "wrap" }}
            >
              <select value={catSubjectType} onChange={(event) => setCatSubjectType(event.target.value)} className="console-select" aria-label="Attribution subject type" data-testid="attr-subject-type-select">
                <option value="link">LINK</option><option value="identifier">IDENTIFIER</option>
                <option value="actor">ACTOR</option><option value="site">SITE</option><option value="finding">FINDING</option>
              </select>
              <Input value={catSubject} onChange={(event) => setCatSubject(event.target.value)} placeholder="Subject (url / value / canon)" aria-label="Attribution subject" data-testid="attr-subject-input" />
              <Input value={catClaim} onChange={(event) => setCatClaim(event.target.value)} placeholder="Claim (optional)" aria-label="Attribution claim" data-testid="attr-claim-input" />
              <select value={catStatement} onChange={(event) => setCatStatement(event.target.value)} className="console-select" aria-label="Attribution statement" data-testid="attr-statement-select">
                <option value="asserts">ASSERTS</option><option value="denies">DENIES</option><option value="disputes">DISPUTES</option>
              </select>
              <input type="range" min="0" max="1" step="0.05" value={catConfidence} onChange={(event) => setCatConfidence(Number(event.target.value))} aria-label="Attribution confidence" />
              <span className="mono">{(catConfidence * 100).toFixed(0)}%</span>
              <Input value={catNote} onChange={(event) => setCatNote(event.target.value)} placeholder="Note" aria-label="Attribution note" data-testid="attr-note-input" />
              <Button type="submit" disabled={!catSubject.trim() || attrMutation.isPending} data-testid="attr-post-button">
                {attrMutation.isPending ? <LoaderCircle className="animate-spin" size={13} /> : <Scale size={13} />} Record
              </Button>
            </form>
          </div>
          <div className="stat-detail-table-stack">
            {(attributionQuery.data ?? []).map((attr) => <AttributionRow key={attr.id} attr={attr} />)}
            {!(attributionQuery.data?.length) && <div className="query-state"><CircleHelp size={16} /> No attribution statements filed.</div>}
          </div>
        </section>
      </main>
    </div>
  );
}