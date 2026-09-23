import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, LoaderCircle, Newspaper, RefreshCw } from "lucide-react";
import { Link } from "react-router-dom";
import { getNews, getText, type NewsItem } from "@/lib/darkforce";

function timeAgo(ts?: string): string {
  if (!ts) return "";
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return ts;
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

export default function News() {
  const queryClient = useQueryClient();
  const newsQuery = useQuery({
    queryKey: ["news"],
    queryFn: () => getNews(60),
    refetchInterval: 15000,
    retry: false,
  });
  const items: NewsItem[] = Array.isArray(newsQuery.data) ? newsQuery.data : [];

  return (
    <div className="console-shell registry-shell">
      <nav className="registry-nav">
        <Link to="/" className="registry-back"><ArrowLeft size={14} /> DARKFORCE CONSOLE</Link>
        <Link to="/resources" className="registry-back" data-testid="news-resources-link">RESOURCES</Link>
        <Link to="/breaches" className="registry-back">BREACHES</Link>
        <span className="registry-title"><Newspaper size={14} /> DARKNET NEWS</span>
        <span className={`mono registry-total ${newsQuery.dataUpdatedAt ? "" : "muted"}`} data-testid="news-live-badge">
          {newsQuery.dataUpdatedAt ? `LIVE · ${items.length} HEADLINES · ${timeAgo(new Date(newsQuery.dataUpdatedAt).toISOString())} AGO` : "LIVE FEED"}
        </span>
      </nav>
      <main className="console-main">
        <section className="registry-toolbar">
          <div className="registry-filter-row">
            <span className="registry-title" style={{ margin: 0 }}>
              <span className="live-dot" /> REALTIME — COLLECTOR UPDATES EVERY 10 MIN
            </span>
            <button
              type="button"
              className="registry-chip"
              data-testid="news-refresh-button"
              onClick={() => { void queryClient.invalidateQueries({ queryKey: ["news"] }); }}
            >
              <RefreshCw size={12} /> REFRESH NOW
            </button>
          </div>
        </section>
        {newsQuery.isLoading ? (
          <div className="query-state"><LoaderCircle className="spin" size={16} /> Pulling latest darknet headlines…</div>
        ) : items.length === 0 ? (
          <div className="query-state" data-testid="news-empty">
            No darknet headlines yet. The collector is scanning the news seed sites on its next passes.
          </div>
        ) : (
          <section className="news-feed" data-testid="news-feed">
            {items.map((n) => (
              <article key={String(n.id)} className="news-card">
                <div className="news-headline">{getText(n.title, "Untitled headline")}</div>
                <div className="news-meta">
                  <span className="category-badge">{(n.site_title || n.site_url || "source").toUpperCase()}</span>
                  <span className="mono">{timeAgo(n.ts)} ago</span>
                  <span className={`status-badge ${/down|blocked/.test(getText(n.status).toLowerCase()) ? "bad-down" : ""}`}>
                    {getText(n.status, "unknown").toUpperCase()}
                  </span>
                  {n.handle && <span className="mono muted">@{n.handle}</span>}
                </div>
                {n.url && <a className="news-link mono" href={n.url} target="_blank" rel="noreferrer" data-testid="news-item-link">{getText(n.url)}</a>}
              </article>
            ))}
          </section>
        )}
      </main>
    </div>
  );
}