/**
 * Tiny client-side table sorting hook. Callers pass an `accessors` map (column
 * key → value extractor); clicking a column header toggles asc/desc. Define the
 * accessors object as a stable module/`useMemo` constant so sorting is cheap.
 */
import { useMemo, useState } from "react";

export type SortDir = "asc" | "desc";
export interface SortState {
  key: string;
  dir: SortDir;
}

export type Accessors<T> = Record<string, (row: T) => string | number>;

export function useSort<T>(rows: T[], accessors: Accessors<T>, initial: SortState | null = null) {
  const [sort, setSort] = useState<SortState | null>(initial);

  const sorted = useMemo(() => {
    if (!sort) return rows;
    const accessor = accessors[sort.key];
    if (!accessor) return rows;
    const dir = sort.dir === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      const va = accessor(a);
      const vb = accessor(b);
      if (typeof va === "number" && typeof vb === "number") return (va - vb) * dir;
      return String(va).localeCompare(String(vb), undefined, { numeric: true }) * dir;
    });
    // accessors is expected to be a stable reference (module const / useMemo).
  }, [rows, sort, accessors]);

  const toggle = (key: string) =>
    setSort((s) =>
      s && s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" },
    );

  return { sorted, sort, toggle };
}
