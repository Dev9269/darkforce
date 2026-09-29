import { lazy, Suspense, useEffect, useState } from "react";
import { Link, Routes, Route } from "react-router-dom";
import { LoaderCircle, SearchX, Moon, Sun } from "lucide-react";
import { Toaster } from "@/components/ui/sonner";

// React.lazy + Suspense keep each page in its own chunk (code-split) and load
// it on first navigation, unlike <Route lazy> which silently renders nothing
// with this router version.
const Home = lazy(() => import("@/pages/Home"));
const Registry = lazy(() => import("@/pages/Registry"));
const Analyst = lazy(() => import("@/pages/Analyst"));
const Evidence = lazy(() => import("@/pages/Evidence"));
const Wallets = lazy(() => import("@/pages/Wallets"));
const Breaches = lazy(() => import("@/pages/Breaches"));
const Cases = lazy(() => import("@/pages/Cases"));
const Resources = lazy(() => import("@/pages/Resources"));
const News = lazy(() => import("@/pages/News"));
const GraphPage = lazy(() => import("@/pages/GraphPage"));
const Legal = lazy(() => import("@/pages/Legal"));

function NotFound() {
  return (
    <div className="console-shell">
      <main className="console-main not-found-main">
        <SearchX size={28} />
        <div className="not-found-code mono">404</div>
        <div className="not-found-title">ROUTE NOT FOUND</div>
        <p className="muted-text">The page you are looking for does not exist in the console.</p>
        <Link to="/" className="console-button">← BACK TO CONSOLE</Link>
      </main>
    </div>
  );
}

function ThemeToggle() {
  const [dark, setDark] = useState(() => {
    try {
      return localStorage.getItem("df-theme") !== "light";
    } catch {
      return true;
    }
  });

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    try {
      localStorage.setItem("df-theme", dark ? "dark" : "light");
    } catch {}
  }, [dark]);

  return (
    <button
      type="button"
      aria-label="Toggle light / dark theme"
      title="Toggle light / dark theme"
      onClick={() => setDark((d) => !d)}
      style={{
        position: "fixed",
        bottom: 12,
        right: 12,
        zIndex: 60,
        width: 34,
        height: 34,
        display: "grid",
        placeItems: "center",
        cursor: "pointer",
        borderRadius: 8,
        border: "1px solid var(--c-border)",
        background: "var(--c-surface)",
        color: "var(--c-text)",
        boxShadow: "0 2px 10px rgba(0,0,0,.18)",
      }}
    >
      {dark ? <Sun size={16} /> : <Moon size={16} />}
    </button>
  );
}

export default function App() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-background route-spinner">
          <LoaderCircle className="animate-spin" size={20} />
          <span className="mono">LOADING MODULE…</span>
        </div>
      }
    >
      <ThemeToggle />
      <Toaster richColors />
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/registry" element={<Registry />} />
        <Route path="/analyst" element={<Analyst />} />
        <Route path="/evidence" element={<Evidence />} />
        <Route path="/wallets" element={<Wallets />} />
        <Route path="/breaches" element={<Breaches />} />
        <Route path="/cases" element={<Cases />} />
        <Route path="/resources" element={<Resources />} />
        <Route path="/news" element={<News />} />
        <Route path="/graph" element={<GraphPage />} />
        <Route path="/terms" element={<Legal docId="terms" />} />
        <Route path="/privacy" element={<Legal docId="privacy" />} />
        <Route path="/cookies" element={<Legal docId="cookies" />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
      <footer className="app-footer">
        <span className="mono">DARKFORCE · RESEARCH CONSOLE</span>
        <nav className="footer-links">
          <Link to="/terms">Terms</Link>
          <Link to="/privacy">Privacy</Link>
          <Link to="/cookies">Cookies</Link>
        </nav>
      </footer>
    </Suspense>
  );
}
