import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { AlertTriangle, ArrowLeft, CircleHelp, Database, LoaderCircle, Search, ShieldAlert, UploadCloud } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  errorText, getBreaches, getPivots, getText, importHibp, importStealer,
  type ImportResult, type PivotResult, type PivotRow,
} from "@/lib/darkforce";

function StealerResult({ result }: { result: ImportResult | undefined }) {
  if (!result) return null;
  return (
    <div className="query-state" data-testid="stealer-import-result">
      <Database size={16} /> Imported <span className="mono">{result.breach}</span> — {result.emails ?? 0} emails, {result.btc ?? 0} BTC, {result.xmr ?? 0} XMR, {result.lines ?? 0} lines, {result.identifiers ?? 0} identifiers ledgered.
    </div>
  );
}

export default function Breaches() {
  const queryClient = useQueryClient();
  const [q, setQ] = useState("");
  const [breachSearch, setBreachSearch] = useState("");
  const [pivotValue, setPivotValue] = useState("");
  const [pivotLookup, setPivotLookup] = useState("");
  const [stealerText, setStealerText] = useState("");
  const [stealerSource, setStealerSource] = useState("stealer_log");

  const breachesQuery = useQuery({ queryKey: ["breaches", breachSearch], queryFn: () => getBreaches(breachSearch || undefined), retry: false });
  const pivotsQuery = useQuery({ queryKey: ["pivots"], queryFn: () => getPivots(), retry: false });
  const pivotLookupQuery = useQuery({
    queryKey: ["pivot-lookup", pivotLookup],
    queryFn: () => getPivots(pivotLookup),
    enabled: Boolean(pivotLookup),
    retry: false,
  });

  const stealerMutation = useMutation({
    mutationFn: () => importStealer(stealerText, stealerSource.trim() || "stealer_log"),
    onSuccess: (result) => {
      toast.success(`Stealer import: ${result.identifiers ?? 0} identifiers`);
      void queryClient.invalidateQueries({ queryKey: ["breaches"] });
      void queryClient.invalidateQueries({ queryKey: ["pivots"] });
    },
    onError: (error) => toast.error(`Stealer import failed: ${errorText(error)}`),
  });
  const hibpMutation = useMutation({
    mutationFn: importHibp,
    onSuccess: (result) => {
      toast.success(`HIBP import: ${result.imported ?? 0} breaches`);
      void queryClient.invalidateQueries({ queryKey: ["breaches"] });
      void queryClient.invalidateQueries({ queryKey: ["pivots"] });
    },
    onError: (error) => toast.error(`HIBP import failed: ${errorText(error)}`),
  });

  const breaches = breachesQuery.data ?? [];
  const allPivots = Array.isArray(pivotsQuery.data) ? pivotsQuery.data : [];
  const pivotResult = !Array.isArray(pivotLookupQuery.data) ? (pivotLookupQuery.data as PivotResult | undefined) : undefined;
  const lookupMatches = (pivotResult?.matches ?? []) as Array<{ name?: string; type?: string; primary_entity?: string; ts_acquired?: string }>;
  const lookupCorpus = pivotResult?.corpus ?? [];

  const submitPivot = (event: React.FormEvent) => {
    event.preventDefault();
    if (pivotValue.trim()) setPivotLookup(pivotValue.trim());
  };

  return (
    <div className="console-shell registry-shell" data-testid="breaches-page">
      <nav className="registry-nav">
        <Link to="/" className="registry-back"><ArrowLeft size={14} /> DARKFORCE CONSOLE</Link>
        <Link to="/wallets" className="registry-back" data-testid="breaches-wallets-link"><ShieldAlert size={14} /> WALLETS</Link>
        <span className="registry-title"><Database size={14} /> BREACH REGISTER — PIVOTS &amp; IMPORTS</span>
        <span className="mono registry-total">{(breaches.length ?? 0).toLocaleString()} BREACH RECORDS</span>
      </nav>
      <main className="console-main">
        <section className="console-panel" data-testid="breaches-list-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker"><Database size={14} /> KNOWN BREACHES</div>
              <div className="panel-subtitle">Acquired datasets, keyed by primary entity</div>
            </div>
            <form onSubmit={(event) => { event.preventDefault(); setBreachSearch(q); }} className="registry-search-form">
              <Search size={16} />
              <input value={q} onChange={(event) => setQ(event.target.value)} placeholder="Search breach name or entity…" aria-label="Search breaches" data-testid="breach-search-input" />
              <button type="submit" className="console-button" disabled={breachesQuery.isFetching}>Search</button>
            </form>
          </div>
          <div className="inventory-table-wrap">
            <table className="inventory-table">
              <thead><tr><th>NAME</th><th>TYPE</th><th>PRIMARY ENTITY</th><th>ACQUIRED</th></tr></thead>
              <tbody>
                {breaches.map((breach) => (
                  <tr key={String(breach.id)}>
                    <td className="mono inventory-value">{getText(breach.name)}</td>
                    <td className="mono">{getText(breach.type, "—")}</td>
                    <td className="mono inventory-value">{getText(breach.primary_entity, "—")}</td>
                    <td className="mono">{getText(breach.ts_acquired, "—")}</td>
                  </tr>
                ))}
                {!breaches.length && (
                  <tr><td colSpan={4} className="muted-text">
                    {breachesQuery.isLoading
                      ? <><LoaderCircle className="animate-spin" size={13} /> Querying breach register…</>
                      : breachesQuery.error
                        ? <span className="query-error">{errorText(breachesQuery.error)}</span>
                        : "No breach records yet — import a stealer log or run the HIBP collector."}
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="console-panel" data-testid="pivot-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker"><ShieldAlert size={14} /> BREACH PIVOTS <span className="mono">/ WHO ELSE LEAKED IN</span></div>
              <div className="panel-subtitle">Corpus identifiers that also surface in a known breach — wallet reuse &amp; email collusion</div>
            </div>
            <form onSubmit={submitPivot} className="pipeline-buttons">
              <Input value={pivotValue} onChange={(event) => setPivotValue(event.target.value)} placeholder="Email or wallet address…" aria-label="Pivot value" data-testid="pivot-value-input" />
              <Button type="submit" disabled={!pivotValue.trim() || pivotLookupQuery.isFetching} data-testid="pivot-lookup-button">
                {pivotLookupQuery.isFetching ? <LoaderCircle className="animate-spin" size={13} /> : <Search size={13} />} Pivot
              </Button>
            </form>
          </div>
          {pivotResult ? (
            <div className="stat-detail-table-stack" data-testid="pivot-result-view">
              <div className="panel-subtitle mono">PIVOT / {pivotResult.query}</div>
              <div className="profile-block">
                <div className="micro-label">BREACH MATCHES</div>
                <div className="inventory-table-wrap">
                  <table className="inventory-table">
                    <thead><tr><th>NAME</th><th>TYPE</th><th>PRIMARY ENTITY</th><th>ACQUIRED</th></tr></thead>
                    <tbody>
                      {lookupMatches.map((match, index) => (
                        <tr key={index}>
                          <td className="mono inventory-value">{getText(match.name)}</td>
                          <td className="mono">{getText(match.type, "—")}</td>
                          <td className="mono">{getText(match.primary_entity, "—")}</td>
                          <td className="mono">{getText(match.ts_acquired, "—")}</td>
                        </tr>
                      ))}
                      {!lookupMatches.length && <tr><td colSpan={4} className="muted-text">No breach matches.</td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>
              <div className="profile-block">
                <div className="micro-label">CORPUS IDENTIFIERS</div>
                <div className="inventory-table-wrap">
                  <table className="inventory-table">
                    <thead><tr><th>KIND</th><th>VALUE</th><th>HANDLE</th></tr></thead>
                    <tbody>
                      {lookupCorpus.map((item) => (
                        <tr key={String(item.id ?? item.value)}>
                          <td><span className="severity-dot db-dot" />{getText(item.kind, "id")}</td>
                          <td className="mono inventory-value">{getText(item.value)}</td>
                          <td className="mono">{getText(item.handle, "—")}</td>
                        </tr>
                      ))}
                      {!lookupCorpus.length && <tr><td colSpan={3} className="muted-text">No corpus identifiers on this pivot.</td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          ) : (
            <div className="query-state"><CircleHelp size={16} /> Enter a value to pivot against the breach corpus.</div>
          )}
        </section>

        <section className="console-panel" data-testid="pivots-crosscorpus-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker"><ShieldAlert size={14} /> CROSS-CORPUS PIVOT INDEX</div>
              <div className="panel-subtitle">Every corpus identifier also present as a breach primary-entity</div>
            </div>
          </div>
          <div className="inventory-table-wrap">
            <table className="inventory-table">
              <thead><tr><th>BREACH</th><th>TYPE</th><th>ENTITY</th><th>KIND</th><th>VALUE</th><th>HANDLE</th></tr></thead>
              <tbody>
                {allPivots.map((pivot: PivotRow, index) => (
                  <tr key={`${pivot.value}-${pivot.name}-${index}`}>
                    <td className="mono inventory-value">{getText(pivot.name)}</td>
                    <td className="mono">{getText(pivot.type, "—")}</td>
                    <td className="mono">{getText(pivot.primary_entity, "—")}</td>
                    <td><span className="severity-dot db-dot" />{getText(pivot.kind, "id")}</td>
                    <td className="mono inventory-value">{getText(pivot.value)}</td>
                    <td className="mono">{getText(pivot.handle, "—")}</td>
                  </tr>
                ))}
                {!allPivots.length && (
                  <tr><td colSpan={6} className="muted-text">
                    {pivotsQuery.isLoading
                      ? <><LoaderCircle className="animate-spin" size={13} /> Building pivot index…</>
                      : pivotsQuery.error
                        ? <span className="query-error">{errorText(pivotsQuery.error)}</span>
                        : "No corpus pivots found yet."}
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="console-panel" data-testid="import-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker"><UploadCloud size={14} /> METADATA IMPORTS</div>
              <div className="panel-subtitle">Safety contract respected — passwords are never stored; only emails + BTC/XMR wallets are ledgered</div>
            </div>
            <div className="pipeline-buttons">
              <span className="micro-label">HIBP COLLECTOR</span>
              <Button variant="outline" size="sm" disabled={hibpMutation.isPending} onClick={() => hibpMutation.mutate()} data-testid="hibp-import-button">
                {hibpMutation.isPending ? <LoaderCircle className="animate-spin" size={13} /> : <Database size={13} />} Import HIBP
              </Button>
            </div>
          </div>
          <form
            onSubmit={(event) => { event.preventDefault(); if (stealerText.trim()) stealerMutation.mutate(); }}
            className="stat-detail-table-stack"
          >
            <Input value={stealerSource} onChange={(event) => setStealerSource(event.target.value)} placeholder="Source name (e.g. stealer_log:2026-09)" aria-label="Stealer source name" data-testid="stealer-source-input" />
            <textarea
              value={stealerText}
              onChange={(event) => setStealerText(event.target.value)}
              placeholder="Paste stealer-log / combo-list lines: emails, BTC addresses, XMR addresses…"
              aria-label="Stealer log text"
              data-testid="stealer-log-textarea"
              rows={6}
              style={{ minHeight: "8rem", border: "1px solid var(--border, #2a3340)", borderRadius: 8, padding: "0.5rem 0.65rem", background: "transparent", fontFamily: "var(--font-mono)", lineHeight: 1.6 }}
            />
            <div className="pipeline-buttons">
              <Button type="submit" disabled={!stealerText.trim() || stealerMutation.isPending} data-testid="stealer-import-button">
                {stealerMutation.isPending ? <LoaderCircle className="animate-spin" size={13} /> : <UploadCloud size={13} />} Ingest metadata
              </Button>
              <StealerResult result={stealerMutation.data} />
            </div>
          </form>
          {stealerMutation.error && (
            <div className="query-state query-error"><AlertTriangle size={16} /> {errorText(stealerMutation.error)}</div>
          )}
        </section>
      </main>
    </div>
  );
}