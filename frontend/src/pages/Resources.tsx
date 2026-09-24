import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Copy, LayoutGrid, Link as LinkIcon, LoaderCircle, PackageSearch } from "lucide-react";
import { Link } from "react-router-dom";
import { getResources, getText, type ResourceSite } from "@/lib/darkforce";

const RESOURCE_CATS = ["free", "resources", "hacking", "malware", "leaked data"];

function statusLabel(status?: string): string {
  const s = (status ?? "").toLowerCase();
  if (!s) return "unscanned";
  if (s.startsWith("blocked")) return s;
  return s;
}

export default function Resources() {
  const [category, setCategory] = useState("");
  const resourcesQuery = useQuery({
    queryKey: ["resources", category],
    queryFn: () => getResources(category || undefined),
    refetchInterval: 15000,
    retry: false,
  });
  const rows: ResourceSite[] = Array.isArray(resourcesQuery.data) ? resourcesQuery.data : [];

  const activeCats = RESOURCE_CATS;

  const copyAddress = async (url?: string) => {
    if (!url) return;
    try { await navigator.clipboard.writeText(url); } catch { return; }
  };

  return (
    <div className="console-shell registry-shell">
      <nav className="registry-nav">
        <Link to="/" className="registry-back"><ArrowLeft size={14} /> DARKFORCE CONSOLE</Link>
        <Link to="/breaches" className="registry-back"><PackageSearch size={14} /> BREACHES</Link>
        <Link to="/news" className="registry-back" data-testid="resources-news-link">NEWS</Link>
        <span className="registry-title"><LayoutGrid size={14} /> DARKNET RESOURCES</span>
        <span className="mono registry-total">{rows.length} FREE-RESOURCE SITES</span>
      </nav>
      <main className="console-main">
        <section className="registry-toolbar">
          <div className="registry-filter-row">
            <button type="button" className={`registry-chip ${category === "" ? "active" : ""}`} onClick={() => setCategory("")}>ALL</button>
            {activeCats.map((cat) => (
              <button type="button" key={cat} className={`registry-chip ${category === cat ? "active" : ""}`} onClick={() => setCategory(cat)}>
                {cat.toUpperCase()}
              </button>
            ))}
          </div>
        </section>
        {resourcesQuery.isLoading ? (
          <div className="query-state"><LoaderCircle className="animate-spin" size={16} /> Scanning resource catalog…</div>
        ) : rows.length === 0 ? (
          <div className="query-state" data-testid="resources-empty">
            No resource sites indexed yet. The collector is probing the resource seed list on its next passes.
          </div>
        ) : (
          <section className="registry-table-wrap" data-testid="resources-table">
            <table className="registry-table">
              <thead><tr><th>SITE</th><th>CATEGORY</th><th>STATUS</th><th>LAST SCAN</th><th>LATEST HEADLINE</th><th /></tr></thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={String(r.id ?? r.url)}>
                    <td>
                      <div className="cell-title">{getText(r.title, "untitled resource")}</div>
                      <div className="cell-meta mono">
                        <span className="onion-addr" data-testid="resource-addr">{getText(r.url)}</span>
                        <button type="button" className="icon-btn" title="Copy address" onClick={() => copyAddress(r.url)}><Copy size={12} /></button>
                      </div>
                    </td>
                    <td><span className="category-badge">{getText(r.category, "other").toUpperCase()}</span></td>
                    <td><span className={`status-badge ${/down|blocked/.test(statusLabel(r.status)) ? "bad-down" : ""}`} data-testid="resource-status">{statusLabel(r.status).toUpperCase()}</span></td>
                    <td className="mono">{getText(r.last_scan).slice(0, 19)}</td>
                    <td className="cell-meta">{getText(r.headline)}</td>
                    <td><LinkIcon size={13} className="muted-icon" /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )}
      </main>
    </div>
  );
}