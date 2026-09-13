import { Routes, Route } from "react-router-dom";
import Home from "@/pages/Home";
import Registry from "@/pages/Registry";
import Analyst from "@/pages/Analyst";

// One <Route> per page in src/pages; BrowserRouter already wraps this in main.tsx.
export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/registry" element={<Registry />} />
      <Route path="/analyst" element={<Analyst />} />
    </Routes>
  );
}
