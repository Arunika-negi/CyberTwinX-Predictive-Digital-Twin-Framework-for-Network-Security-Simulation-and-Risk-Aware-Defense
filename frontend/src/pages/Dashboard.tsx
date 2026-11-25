
import { useState } from "react";
import {
    ReactFlow,
    Background,
    Controls,
    MiniMap,
    Handle,
    Position,
    type Node,
    type Edge,
    type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
    RefreshCw,
    Network,
    ShieldAlert,
    Server,
    Bug,
    Route,
} from "lucide-react";

type AssetNodeData = {
    label: string;
    address: string;
    category: string;
};

function AssetNode({ data }: NodeProps<Node<AssetNodeData>>) {
    const colors: Record<string, string> = {
        critical: "border-red-500 bg-red-500/15 text-red-400",
        server: "border-orange-500 bg-orange-500/15 text-orange-400",
        asset: "border-blue-500 bg-blue-500/15 text-blue-400",
        vulnerability: "border-purple-500 bg-purple-500/15 text-purple-400",
    };

    return (
        <div className={`min-w-36 rounded-xl border-2 p-3 shadow-xl ${colors[data.category] || colors.asset}`}>
            <Handle type="target" position={Position.Top} className="!bg-slate-400" />
            <div className="flex items-center gap-2">
                <Server size={17} />
                <span className="text-xs font-bold">{data.label}</span>
            </div>
            <p className="mt-2 text-[10px] opacity-70">{data.address}</p>
            <Handle type="source" position={Position.Bottom} className="!bg-slate-400" />
        </div>
    );
}

const nodeTypes = { assetNode: AssetNode };

const initialNodes: Node<AssetNodeData>[] = [
    {
        id: "1",
        type: "assetNode",
        position: { x: 100, y: 80 },
        data: { label: "Workstation", address: "192.168.1.10", category: "asset" },
    },
    {
        id: "2",
        type: "assetNode",
        position: { x: 380, y: 80 },
        data: { label: "Application Server", address: "192.168.1.20", category: "server" },
    },
    {
        id: "3",
        type: "assetNode",
        position: { x: 380, y: 280 },
        data: { label: "Database Server", address: "192.168.1.30", category: "critical" },
    },
    {
        id: "4",
        type: "assetNode",
        position: { x: 100, y: 280 },
        data: { label: "Vulnerability", address: "CVE finding", category: "vulnerability" },
    },
];

const initialEdges: Edge[] = [
    { id: "e1-2", source: "1", target: "2", animated: true },
    { id: "e2-3", source: "2", target: "3", animated: true, style: { stroke: "#ef4444", strokeWidth: 2 } },
    { id: "e4-3", source: "4", target: "3", style: { stroke: "#a78bfa" } },
];

const statistics = [
    { label: "Network Nodes", value: "—", icon: Network, color: "text-blue-400" },
    { label: "Assets", value: "—", icon: Server, color: "text-cyan-400" },
    { label: "Vulnerabilities", value: "—", icon: Bug, color: "text-red-400" },
    { label: "Attack Paths", value: "—", icon: Route, color: "text-purple-400" },
];

export default function Dashboard() {
    const [activeTab, setActiveTab] = useState("Graph View");

    return (
        <div className="min-h-full bg-[#0b1220] p-6 text-slate-200">
            <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
                <div>
                    <h2 className="text-2xl font-bold text-white">Network Digital Twin</h2>
                    <p className="mt-1 text-sm text-slate-400">
                        Visualize assets, vulnerabilities and network relationships
                    </p>
                </div>

                <button className="flex items-center gap-2 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">
                    <RefreshCw size={16} />
                    Refresh data
                </button>
            </div>

            <div className="mb-5 flex gap-6 border-b border-slate-800">
                {["Graph View", "Attack Paths", "Simulation"].map((tab) => (
                    <button
                        key={tab}
                        onClick={() => setActiveTab(tab)}
                        className={`border-b-2 px-2 pb-3 text-sm ${activeTab === tab
                                ? "border-blue-400 font-semibold text-blue-400"
                                : "border-transparent text-slate-400 hover:text-white"
                            }`}
                    >
                        {tab}
                    </button>
                ))}
            </div>

            <div className="grid grid-cols-1 gap-5 2xl:grid-cols-[minmax(0,1fr)_340px]">
                <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#101a2e]">
                    <div className="flex flex-wrap items-center gap-5 border-b border-slate-800 p-4 text-xs text-slate-400">
                        <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-full bg-blue-500" /> Asset</span>
                        <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-full bg-red-500" /> Critical asset</span>
                        <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-full bg-orange-500" /> Server</span>
                        <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-full bg-purple-500" /> Finding</span>
                    </div>

                    {activeTab === "Graph View" ? (
                        <div className="h-[580px]">
                            <ReactFlow
                                nodes={initialNodes}
                                edges={initialEdges}
                                nodeTypes={nodeTypes}
                                fitView
                                proOptions={{ hideAttribution: true }}
                            >
                                <Background color="#26364e" gap={22} />
                                <Controls />
                                <MiniMap nodeColor="#3b82f6" />
                            </ReactFlow>
                        </div>
                    ) : (
                        <div className="flex h-[580px] items-center justify-center p-8 text-center">
                            <div>
                                <Network size={40} className="mx-auto mb-4 text-slate-600" />
                                <h3 className="text-lg font-semibold text-white">{activeTab}</h3>
                                <p className="mt-2 text-sm text-slate-400">
                                    Connect the corresponding backend module to display verified results.
                                </p>
                            </div>
                        </div>
                    )}
                </div>

                <div className="space-y-5">
                    <div className="grid grid-cols-2 gap-3">
                        {statistics.map((item) => {
                            const Icon = item.icon;
                            return (
                                <div key={item.label} className="rounded-xl border border-slate-800 bg-[#101a2e] p-4">
                                    <Icon size={20} className={item.color} />
                                    <p className="mt-3 text-2xl font-bold text-white">{item.value}</p>
                                    <p className="mt-1 text-xs text-slate-400">{item.label}</p>
                                </div>
                            );
                        })}
                    </div>

                    <div className="rounded-xl border border-slate-800 bg-[#101a2e] p-5">
                        <div className="mb-4 flex items-center gap-2">
                            <ShieldAlert size={19} className="text-red-400" />
                            <h3 className="font-semibold text-white">Risk Overview</h3>
                        </div>
                        <p className="text-sm text-slate-400">
                            Risk statistics will appear when the risk assessment API is connected.
                        </p>
                    </div>

                    <div className="rounded-xl border border-slate-800 bg-[#101a2e] p-5">
                        <h3 className="mb-3 font-semibold text-white">Attack Path Analysis</h3>
                        <p className="text-sm text-slate-400">
                            Candidate paths and critical chokepoints will be displayed here from the NetworkX analysis.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
}
