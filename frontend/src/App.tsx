
import { Routes, Route } from "react-router-dom";
import Sidebar from "./layouts/Sidebar";
import Topbar from "./layouts/Topbar";
import Dashboard from "./pages/Dashboard";

function SectionPage({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="min-h-full bg-[#0b1220] p-8 text-slate-200">
      <h1 className="text-2xl font-bold text-white">{title}</h1>
      <p className="mt-2 text-sm text-slate-400">{description}</p>

      <div className="mt-8 rounded-xl border border-slate-800 bg-[#101a2e] p-6">
        <p className="font-semibold text-slate-300">
          Waiting for backend integration
        </p>
        <p className="mt-2 text-sm text-slate-400">
          This section will display verified project data when its FastAPI
          endpoint is connected.
        </p>
      </div>
    </div>
  );
}

function App() {
  return (
    <div className="flex h-screen overflow-hidden bg-[#0b1220]">
      <Sidebar />

      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />

        <main className="min-h-0 flex-1 overflow-y-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/network" element={<Dashboard />} />

            <Route
              path="/assets"
              element={
                <SectionPage
                  title="Asset Inventory"
                  description="View discovered hosts, operating systems, ports and services."
                />
              }
            />

            <Route
              path="/vulnerabilities"
              element={
                <SectionPage
                  title="Vulnerability Intelligence"
                  description="Review matched CVEs, CVSS scores and exploitation evidence."
                />
              }
            />

            <Route
              path="/risk"
              element={
                <SectionPage
                  title="Risk Assessment"
                  description="Review contextual risk scores and prioritized assets."
                />
              }
            />

            <Route
              path="/attack-paths"
              element={
                <SectionPage
                  title="Attack Path Analysis"
                  description="Explore candidate attack paths and critical network chokepoints."
                />
              }
            />

            <Route
              path="/simulation"
              element={
                <SectionPage
                  title="What-if Defense Simulation"
                  description="Evaluate proposed firewall restrictions and compare network reachability."
                />
              }
            />

            <Route
              path="*"
              element={
                <SectionPage
                  title="Page not found"
                  description="The requested dashboard page does not exist."
                />
              }
            />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default App;

