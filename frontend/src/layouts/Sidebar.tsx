

import { NavLink } from "react-router-dom";
import {
    LayoutDashboard,
    Monitor,
    Bug,
    ShieldCheck,
    Network,
    GitBranch,
    SlidersHorizontal,
} from "lucide-react";

const navigation = [
    { label: "Overview", path: "/", icon: LayoutDashboard },
    { label: "Assets", path: "/assets", icon: Monitor },
    { label: "Vulnerabilities", path: "/vulnerabilities", icon: Bug },
    { label: "Risk Assessment", path: "/risk", icon: ShieldCheck },
    { label: "Network Graph", path: "/network", icon: Network },
    { label: "Attack Paths", path: "/attack-paths", icon: GitBranch },
    { label: "Simulation", path: "/simulation", icon: SlidersHorizontal },
];

export default function Sidebar() {
    return (
        <aside className="flex h-screen w-64 shrink-0 flex-col border-r border-slate-800 bg-[#101827] text-slate-300">
            <div className="flex h-20 items-center gap-3 border-b border-slate-800 px-6">
                <div className="rounded-lg bg-blue-500/15 p-2">
                    <ShieldCheck className="h-7 w-7 text-blue-400" />
                </div>
                <div>
                    <h1 className="text-lg font-bold tracking-wide text-white">
                        CYBERTWIN-X
                    </h1>
                    <p className="text-xs text-slate-500">Network Security</p>
                </div>
            </div>

            <div className="px-4 py-6">
                <p className="mb-3 px-3 text-xs font-semibold uppercase tracking-widest text-slate-500">
                    Workspace
                </p>

                <nav className="space-y-1">
                    {navigation.map((item) => {
                        const Icon = item.icon;

                        return (
                            <NavLink
                                key={item.path}
                                to={item.path}
                                end={item.path === "/"}
                                className={({ isActive }) =>
                                    `flex w-full items-center gap-3 rounded-lg px-3 py-3 text-sm transition ${isActive
                                        ? "bg-blue-500/15 text-blue-400"
                                        : "text-slate-400 hover:bg-slate-800 hover:text-white"
                                    }`
                                }
                            >
                                <Icon size={19} />
                                {item.label}
                            </NavLink>
                        );
                    })}
                </nav>
            </div>

            <div className="mt-auto border-t border-slate-800 p-5">
                <p className="text-xs text-slate-500">CyberTwin-X</p>
                <p className="mt-1 text-xs text-slate-400">
                    Digital Twin Security Framework
                </p>
            </div>
        </aside>
    );
}
