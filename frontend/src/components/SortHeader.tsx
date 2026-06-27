/** Clickable, sort-aware table header cell. Pairs with the useSort hook. */
import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";
import type { SortState } from "../lib/use-sort";

interface Props {
  label: string;
  colKey: string;
  sort: SortState | null;
  toggle: (key: string) => void;
  align?: "left" | "right";
  className?: string;
}

export default function SortHeader({
  label,
  colKey,
  sort,
  toggle,
  align = "left",
  className = "",
}: Props) {
  const active = sort?.key === colKey;
  const Icon = !active ? ChevronsUpDown : sort.dir === "asc" ? ArrowUp : ArrowDown;
  return (
    <th className={`px-3 py-2 ${className}`}>
      <button
        type="button"
        onClick={() => toggle(colKey)}
        className={`inline-flex items-center gap-1 hover:text-slate-300 ${
          align === "right" ? "flex-row-reverse" : ""
        }`}
      >
        {label}
        <Icon className={`h-3 w-3 ${active ? "text-emerald-400" : "text-slate-600"}`} />
      </button>
    </th>
  );
}
