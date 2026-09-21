import { Routes, Route } from "react-router-dom";

// One <Route> per page in src/pages; BrowserRouter already wraps this in main.tsx.
// Route.lazy code-splits each page: the shared chunk stays in the entry bundle
// and every page loads only when first navigated to.
export default function App() {
  return (
    <Routes>
      <Route path="/" lazy={() => import("@/pages/Home")} />
      <Route path="/registry" lazy={() => import("@/pages/Registry")} />
      <Route path="/analyst" lazy={() => import("@/pages/Analyst")} />
      <Route path="/evidence" lazy={() => import("@/pages/Evidence")} />
      <Route path="/wallets" lazy={() => import("@/pages/Wallets")} />
      <Route path="/breaches" lazy={() => import("@/pages/Breaches")} />
      <Route path="/cases" lazy={() => import("@/pages/Cases")} />
      <Route path="/resources" lazy={() => import("@/pages/Resources")} />
      <Route path="/news" lazy={() => import("@/pages/News")} />
    </Routes>
  );
}
