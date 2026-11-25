
import { Search, Bell, CircleHelp } from "lucide-react";

export default function Topbar() {
    return (
        <header className="flex h-[76px] items-center justify-between border-b border-slate-800 bg-[#101827] px-7">
            <div className="flex w-full max-w-xl items-center gap-3 rounded-lg border border-slate-700 bg-[#182438] px-4 py-3">
                <Search size={19} className="text-slate-400" />
                <input
                    type="text"
                    placeholder="Search assets, findings, CVEs..."
                    className="w-full bg-transparent text-sm text-white outline-none placeholder:text-slate-500"
                />
            </div>

            <div className="ml-6 flex items-center gap-6">
                <button className="text-slate-400 hover:text-white">
                    <Bell size={20} />
                </button>

                <button className="text-slate-400 hover:text-white">
                    <CircleHelp size={20} />
                </button>

                <div className="border-l border-slate-700 pl-5">
                    <p className="text-sm font-semibold text-white">Security Analyst</p>
                    <p className="text-xs text-slate-500">CyberTwin-X Workspace</p>
                </div>

                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-blue-500/20 text-sm font-bold text-blue-400">
                    CX
                </div>
            </div>
        </header>
    );
}
