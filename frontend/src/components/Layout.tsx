import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth";

const links = [
  ["/", "Overview"], ["/repositories", "Repositories"], ["/scans", "Scans"], ["/findings", "Findings"], ["/policies", "Policies"], ["/settings", "Integrations & audit"],
] as const;

export default function Layout() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  return (
    <div className="min-h-screen md:flex">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-white focus:p-2">Skip to content</a>
      <header className="flex items-center justify-between bg-slate-900 px-4 py-3 text-white md:hidden">
        <span className="font-bold">PipelineGuard</span>
        <button aria-expanded={open} aria-controls="nav" onClick={() => setOpen(!open)} className="rounded px-2 py-1 ring-1 ring-slate-600">Menu</button>
      </header>
      <nav id="nav" aria-label="Main" className={`${open ? "block" : "hidden"} w-full shrink-0 bg-slate-900 p-4 text-slate-200 md:block md:min-h-screen md:w-60`}>
        <div className="mb-6 hidden items-center gap-2 text-lg font-bold text-white md:flex">
          <span aria-hidden className="inline-block h-6 w-6 rounded bg-emerald-400" />PipelineGuard
        </div>
        <ul className="space-y-1">
          {links.map(([to, label]) => (
            <li key={to}>
              <NavLink to={to} end={to === "/"} onClick={() => setOpen(false)}
                className={({ isActive }) => `block rounded-md px-3 py-2 text-sm ${isActive ? "bg-slate-700 font-semibold text-white" : "hover:bg-slate-800"}`}>{label}</NavLink>
            </li>
          ))}
        </ul>
        <div className="mt-8 border-t border-slate-700 pt-4 text-xs">
          <div className="truncate font-medium text-white">{user?.email}</div>
          <div className="mb-2 text-slate-400">{user?.role.replace("_", " ")}</div>
          <button onClick={logout} className="rounded bg-slate-800 px-3 py-1.5 hover:bg-slate-700">Sign out</button>
        </div>
      </nav>
      <main id="main" className="min-w-0 flex-1 p-4 md:p-8"><Outlet /></main>
    </div>
  );
}
