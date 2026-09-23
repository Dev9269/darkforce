import { lazy, Suspense } from "react";
import { Routes, Route } from "react-router-dom";

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

export default function App() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-background" />}>
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
      </Routes>
    </Suspense>
  );
}
