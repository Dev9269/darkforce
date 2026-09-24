import { lazy, Suspense } from "react";
import { Link, Routes, Route } from "react-router-dom";
import { LoaderCircle, SearchX } from "lucide-react";
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
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Suspense>
  );
}
