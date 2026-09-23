import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Globe2, Search, LayoutGrid, ArrowLeft, AlertTriangle, CircleHelp, LoaderCircle, Network } from "lucide-react";
import { Link } from "react-router-dom";
import { getCategories, getSiteCatalog, getText, type JsonRecord } from "@/lib/darkforce";

const PER_PAGE = 100;

function purposeBadge(purpose?: string) {
  const danger = ["drugs", "weapons", "hitman", "porn", "child", "cp", "leaked data"].some((k) => purpose?.includes(k));
  return <span className={`purpose-tag ${danger ? "purpose-danger" : "purpose-ok"}`}>{purpose ?? "unknown"}</span>;
}

export default function Registry() {
  const [category, setCategory] = useState<string>("");
  const [q, setQ] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [page, setPage] = useState(1);

  const categoriesQuery = useQuery({ queryKey: ["categories"], queryFn: getCategories, refetchInterval: 15000, retry: false });
  const categories = categoriesQuery.data?.categories ?? [];

  const catalogQuery = useQuery({
    queryKey: ["catalog", category, searchInput, page],
    queryFn: () => getSiteCatalog({ category: category || undefined, q: searchInput || undefined, page, perPage: PER_PAGE }),
    refetchInterval: 15000,
    retry: false,
  });

  const rows = catalogQuery.data?.items ?? [];
  const total = catalogQuery.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));
  const counts = (categoriesQuery.data as { counts?: Record<string, number> } | undefined)?.counts;

  const submitSearch = (event: React.FormEvent) => {
    event.preventDefault();
    setPage(1);
    setSearchInput(q);
  };
  const pickCategory = (value: string) => {
    setCategory(value);
    setPage(1);
  };

  const nav = (
    <nav className="registry-nav">
      <Link to="/" className="registry-back"><ArrowLeft size={14} /> DARKFORCE CONSOLE</Link>
      <Link to="/analyst" className="registry-back" data-testid="registry-analyst-link"><Network size={14} /> ANALYST</Link>
      <Link to="/evidence" className="registry-back" data-testid="registry-evidence-link">EVIDENCE</Link>
      <Link to="/wallets" className="registry-back" data-testid="registry-wallets-link">WALLETS</Link>
      <Link to="/breaches" className="registry-back" data-testid="registry-breaches-link">BREACHES</Link>
      <Link to="/cases" className="registry-back" data-testid="registry-cases-link">CASES</Link>
      <span className="registry-title"><LayoutGrid size={14} /> MASTER REGISTRY — SITE INVENTORY</span>
      <span className="mono registry-total">{total.toLocaleString()} INDEXED SITES</span>
    </nav>
  );

  return (
    <div className="console-shell registry-shell">
      {nav}
      <main className="console-main">
        <section className="registry-toolbar">
          <div className="registry-filter-row">
            <button type="button" className={`registry-chip ${category === "" ? "active" : ""}`} onClick={() => pickCategory("")}>ALL</button>
            {categories.map((cat) => (
              <button type="button" key={cat} className={`registry-chip ${category === cat ? "active" : ""}`} onClick={() => pickCategory(cat)}>
                {cat.toUpperCase()}<span className="mono">{counts?.[cat] ?? 0}</span>
              </button>
            ))}
          </div>
          <form onSubmit={submitSearch} className="registry-search-form">
            <Search size={16} />
            <input value={q} onChange={(event) => setQ(event.target.value)} placeholder="Search by URL or title…" aria-label="Search registry" data-testid="registry-search-input" />
            <button type="submit" className="console-button" disabled={catalogQuery.isFetching}>Search</button>
          </form>
        </section>

        {catalogQuery.isLoading ? (
          <div className="query-state"><LoaderCircle className="animate-spin" size={16} /> Querying source…</div>
        ) : catalogQuery.error ? (
          <div className="query-state query-error"><AlertTriangle size={16} /> {String(catalogQuery.error)}</div>
        ) : !rows.length ? (
          <div className="query-state"><CircleHelp size={16} /> No records match this filter.</div>
        ) : (
          <div className="inventory-table-wrap registry-table-wrap">
            <table className="inventory-table">
              <thead><tr><th>PURPOSE</th><th>URL</th><th>TITLE</th><th>LANG</th><th>DESCRIPTION</th><th>SEEN</th></tr></thead>
              <tbody>
                {rows.map((site: JsonRecord) => (
                  <tr key={String(site.id)}>
                    <td>{purposeBadge(getText(site.category, getText(site.purpose, "other")))}</td>
                    <td className="mono inventory-url"><a href={getText(site.url)} target="_blank" rel="noreferrer noopener">{getText(site.url)}</a></td>
                    <td className="inventory-detail">{getText(site.title, "—")}</td>
                    <td className="mono">{getText(site.lang, "—")}</td>
                    <td className="inventory-detail">{getText(site.desc, getText(site.snip, "—"))}</td>
                    <td className="mono">{getText(site.first_seen, "—")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {totalPages > 1 && (
          <div className="registry-pager">
            <button type="button" className="console-button" disabled={page <= 1} onClick={() => setPage((page) => page - 1)}>← PREV</button>
            <span className="mono">PAGE {page} / {totalPages} · {(catalogQuery.data?.items?.length ?? 0)} of {total.toLocaleString()}</span>
            <button type="button" className="console-button" disabled={page >= totalPages} onClick={() => setPage((page) => page + 1)}>NEXT →</button>
          </div>
        )}
      </main>
    </div>
  );
}