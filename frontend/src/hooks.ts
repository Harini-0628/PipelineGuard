import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "./api/client";

export interface Async<T> { data: T | null; error: string | null; loading: boolean; reload: () => void }

/** Loads data, tracks loading/error, and ignores stale responses. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): Async<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const seq = useRef(0);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const run = useCallback(fn, deps);
  useEffect(() => {
    const id = ++seq.current;
    setLoading(true);
    run().then((d) => { if (id === seq.current) { setData(d); setError(null); } })
      .catch((e: unknown) => { if (id === seq.current) setError(e instanceof ApiError ? e.message : "Unexpected error"); })
      .finally(() => { if (id === seq.current) setLoading(false); });
  }, [run, tick]);
  return { data, error, loading, reload: () => setTick((t) => t + 1) };
}

export const fmtDate = (s: string | null | undefined) => (s ? new Date(s).toLocaleString() : "-");
export const short = (sha: string) => sha.slice(0, 8);
