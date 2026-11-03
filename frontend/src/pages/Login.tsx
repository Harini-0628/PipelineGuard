import { useState, type SyntheticEvent } from "react";
import { useAuth } from "../auth";
import { Button, ErrorBox } from "../components/ui";

export default function Login() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(e: SyntheticEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try { await login(email, password); } catch (err) { setError(err instanceof Error ? err.message : "Sign-in failed"); } finally { setBusy(false); }
  }
  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-900 p-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-xl bg-white p-6 shadow-xl">
        <div><h1 className="text-xl font-bold">PipelineGuard</h1><p className="text-sm text-slate-500">Sign in to the security console</p></div>
        {error && <ErrorBox message={error} />}
        <label className="block text-sm font-medium">Email
          <input type="email" required autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2" /></label>
        <label className="block text-sm font-medium">Password
          <input type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2" /></label>
        <Button type="submit" disabled={busy} className="w-full">{busy ? "Signing in…" : "Sign in"}</Button>
      </form>
    </div>
  );
}
