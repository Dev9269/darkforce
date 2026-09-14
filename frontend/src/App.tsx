import { Routes, Route } from "react-router-dom";
import Home from "@/pages/Home";
import Registry from "@/pages/Registry";
import Analyst from "@/pages/Analyst";
import Evidence from "@/pages/Evidence";
import Wallets from "@/pages/Wallets";
import Breaches from "@/pages/Breaches";
import Cases from "@/pages/Cases";

// One <Route> per page in src/pages; BrowserRouter already wraps this in main.tsx.
export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/registry" element={<Registry />} />
      <Route path="/analyst" element={<Analyst />} />
      <Route path="/evidence" element={<Evidence />} />
      <Route path="/wallets" element={<Wallets />} />
      <Route path="/breaches" element={<Breaches />} />
      <Route path="/cases" element={<Cases />} />
    </Routes>
  );
}
