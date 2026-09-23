import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { AlertTriangle, ArrowLeft, Bitcoin, CircleHelp, FileJson, Fingerprint, LoaderCircle, Search } from "lucide-react";
import { Link } from "react-router-dom";
import {
  errorText, getText, getWallet, getWallets,
  type Wallet,
} from "@/lib/darkforce";

const KIND_OPTIONS = [
  { value: "", label: "ALL KINDS" },
  { value: "btc", label: "BTC" },
  { value: "xmr", label: "XMR" },
];

export default function Wallets() {
  const [q, setQ] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [kind, setKind] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);

  const listQuery = useQuery({
    queryKey: ["wallets", searchInput, kind, page],
    queryFn: () => getWallets({ q: searchInput || undefined, kind: kind || undefined, page, perPage: 50 }),
    refetchInterval: 15000,
    retry: false,
  });
  const detailQuery = useQuery({
    queryKey: ["wallet", selected],
    queryFn: () => getWallet(selected!),
    enabled: Boolean(selected),
    refetchInterval: 15000,
    retry: false,
  });

  const rows = listQuery.data?.items ?? [];
  const total = listQuery.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / 50));
  const detail = detailQuery.data;

  const submitSearch = (event: React.FormEvent) => {
    event.preventDefault();
    setPage(1);
    setSearchInput(q);
  };

  return (
    <div className="console-shell registry-shell" data-testid="wallets-page">
      <nav className="registry-nav">
        <Link to="/" className="registry-back"><ArrowLeft size={14} /> DARKFORCE CONSOLE</Link>
        <Link to="/breaches" className="registry-back" data-testid="wallets-breaches-link"><FileJson size={14} /> BREACHES</Link>
        <span className="registry-title"><Bitcoin size={14} /> WALLET REGISTER — BTC / XMR REUSE</span>
        <span className="mono registry-total">{total.toLocaleString()} INDEXED WALLETS</span>
      </nav>
      <main className="console-main">
        <section className="registry-toolbar">
          <div className="registry-filter-row">
            {KIND_OPTIONS.map((option) => (
              <button
                type="button"
                key={option.value}
                className={`registry-chip ${kind === option.value ? "active" : ""}`}
                onClick={() => { setKind(option.value); setPage(1); }}
              >
                {option.label}
              </button>
            ))}
          </div>
          <form onSubmit={submitSearch} className="registry-search-form">
            <Search size={16} />
            <input value={q} onChange={(event) => setQ(event.target.value)} placeholder="Search by address…" aria-label="Search wallets" data-testid="wallet-search-input" />
            <button type="submit" className="console-button" disabled={listQuery.isFetching}>Search</button>
          </form>
        </section>

        <section className="console-panel" data-testid="wallets-list-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker"><Bitcoin size={14} /> REUSED WALLETS</div>
              <div className="panel-subtitle">Select an address to expand its transitive cluster</div>
            </div>
            <span className="mono muted-text">{total.toLocaleString()} TOTAL</span>
          </div>
          <div className="inventory-table-wrap">
            <table className="inventory-table">
              <thead><tr><th>KIND</th><th>ADDRESS</th><th>CATEGORY</th><th>IDENTIFIERS</th><th>LAST SEEN</th></tr></thead>
              <tbody>
                {rows.map((wallet: Wallet) => (
                  <tr key={String(wallet.id)} onClick={() => setSelected(wallet.address ?? null)} style={{ cursor: "pointer" }}>
                    <td><span className="severity-dot db-dot" />{getText(wallet.kind, "—").toUpperCase()}</td>
                    <td className="mono inventory-value">{getText(wallet.address)}</td>
                    <td className="inventory-detail">{getText(wallet.category, "—")}</td>
                    <td className="mono">{Number(wallet.n_identifiers ?? 0)}</td>
                    <td className="mono">{getText(wallet.last_seen, "—")}</td>
                  </tr>
                ))}
                {!rows.length && (
                  <tr><td colSpan={5} className="muted-text">
                    {listQuery.isLoading
                      ? <><LoaderCircle className="animate-spin" size={13} /> Querying wallet register…</>
                      : listQuery.error
                        ? <span className="query-error">{errorText(listQuery.error)}</span>
                        : "No wallets match."}
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
          {totalPages > 1 && (
            <div className="registry-pager">
              <button type="button" className="console-button" disabled={page <= 1} onClick={() => setPage((page) => page - 1)}>← PREV</button>
              <span className="mono">PAGE {page} / {totalPages}</span>
              <button type="button" className="console-button" disabled={page >= totalPages} onClick={() => setPage((page) => page + 1)}>NEXT →</button>
            </div>
          )}
        </section>

        <section className="console-panel" data-testid="wallet-detail-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker"><Fingerprint size={14} /> CLUSTER <span className="mono">/ TRANSITIVE CLOSURE</span></div>
              <div className="panel-subtitle">Casual offenders reuse wallets across markets — this walks every actor/handle the address touches</div>
            </div>
          </div>
          {selected && detailQuery.isLoading ? (
            <div className="query-state"><LoaderCircle className="animate-spin" size={16} /> Expanding cluster…</div>
          ) : selected && detailQuery.error ? (
            <div className="query-state query-error"><AlertTriangle size={16} /> {errorText(detailQuery.error)}</div>
          ) : detail ? (
            <div className="stat-detail-table-stack" data-testid="wallet-cluster-view">
              <div className="profile-hero">
                <div className="profile-name-block">
                  <div className="profile-handle mono">{detail.address}</div>
                  <div className="profile-meta">{getText(detail.kind, "?")} · {getText(detail.category, "unknown category")} · {detail.cluster?.wallets?.length ?? 0} cluster wallets</div>
                  <div className="profile-meta mono muted-text">
                    {detail.first_seen && `First seen ${getText(detail.first_seen)}`}
                    {detail.last_seen && ` · Last seen ${getText(detail.last_seen)}`}
                    {detail.posts && detail.posts.length > 0 && ` · ${detail.posts.length} post(s) referencing`}
                    {detail.observations && detail.observations.length > 0 && ` · ${detail.observations.length} extraction(s)`}
                  </div>
                </div>
              </div>
              <div className="profile-columns">
                <div className="profile-block">
                  <div className="micro-label">CLUSTER WALLETS</div>
                  <div className="tag-list">
                    {(detail.cluster?.wallets ?? []).map((value) => (
                      <button type="button" className="data-tag mono" key={value} onClick={() => { setSelected(value); void toast.info(`Expanding wallet ${value}`); }}>{value}</button>
                    ))}
                    {!(detail.cluster?.wallets?.length) && <span className="muted-text">No connected wallets.</span>}
                  </div>
                </div>
                <div className="profile-block">
                  <div className="micro-label">LINKED HANDLES</div>
                  <div className="tag-list">
                    {(detail.cluster?.handles ?? []).map((handle) => <span className="data-tag mono" key={handle}>{handle}</span>)}
                    {!(detail.cluster?.handles?.length) && <span className="muted-text">No linked handles.</span>}
                  </div>
                </div>
                <div className="profile-block">
                  <div className="micro-label">ACTOR RECORDS</div>
                  <div className="tag-list">
                    {(detail.cluster?.actors ?? []).map((actorId) => <span className="data-tag mono" key={actorId}>actor #{actorId}</span>)}
                    {!(detail.cluster?.actors?.length) && <span className="muted-text">Not attributed to any actor.</span>}
                  </div>
                </div>
              </div>
              <div className="profile-block">
                <div className="micro-label">CORPUS IDENTIFIERS</div>
                <div className="inventory-table-wrap">
                  <table className="inventory-table">
                    <thead><tr><th>KIND</th><th>VALUE</th><th>DETAIL</th></tr></thead>
                    <tbody>
                      {(detail.identifiers ?? []).map((item) => (
                        <tr key={String(item.id ?? item.value)}>
                          <td><span className="severity-dot db-dot" />{getText(item.kind, "id")}</td>
                          <td className="mono inventory-value">{getText(item.value)}</td>
                          <td className="inventory-detail">{getText(item.detail, "—")}</td>
                        </tr>
                      ))}
                      {!(detail.identifiers?.length) && <tr><td colSpan={3} className="muted-text">No identifiers reference this address.</td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>
              {detail.posts && detail.posts.length > 0 && (
                <div className="profile-block">
                  <div className="micro-label">POSTS REFERENCING THIS WALLET</div>
                  <div className="inventory-table-wrap">
                    <table className="inventory-table">
                      <thead><tr><th>DATE</th><th>SITE</th><th>TITLE</th></tr></thead>
                      <tbody>
                        {detail.posts.slice(0, 10).map((post) => (
                          <tr key={String(post.id)}>
                            <td className="mono">{getText(post.ts).slice(0, 19)}</td>
                            <td className="mono inventory-url"><a href={post.site_url} target="_blank" rel="noreferrer">{getText(post.site_url)}</a></td>
                            <td className="inventory-detail">{getText(post.title, "—")}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
              {detail.observations && detail.observations.length > 0 && (
                <div className="profile-block">
                  <div className="micro-label">EXTRACTIONS (OBSERVATIONS)</div>
                  <div className="inventory-table-wrap">
                    <table className="inventory-table">
                      <thead><tr><th>DATE</th><th>METHOD</th><th>KIND</th><th>SOURCE</th><th>SITE</th></tr></thead>
                      <tbody>
                        {detail.observations.slice(0, 10).map((obs) => (
                          <tr key={String(obs.id)}>
                            <td className="mono">{getText(obs.ts).slice(0, 19)}</td>
                            <td className="mono">{getText(obs.method, "—")}</td>
                            <td><span className="severity-dot db-dot" />{getText(obs.kind, "—")}</td>
                            <td className="mono">{getText(obs.source_name, "—")}</td>
                            <td className="mono inventory-url"><a href={obs.site_url} target="_blank" rel="noreferrer">{getText(obs.site_url)}</a></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="query-state"><CircleHelp size={16} /> Select a wallet above to expand its reuse cluster.</div>
          )}
        </section>
      </main>
    </div>
  );
}