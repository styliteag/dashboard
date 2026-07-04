export default function KpiTile({
  label,
  value,
  color,
  onClick,
  active,
}: {
  label: string;
  value: number;
  color: string;
  onClick?: () => void;
  active?: boolean;
}) {
  const inner = (
    <>
      <p className="text-xs text-slate-500">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
    </>
  );
  if (!onClick) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3">{inner}</div>
    );
  }
  return (
    <button
      onClick={onClick}
      className={`rounded-xl border bg-slate-900/60 px-4 py-3 text-left ${
        active
          ? "border-emerald-600 ring-1 ring-emerald-600/60"
          : "border-slate-800 hover:border-slate-600 hover:bg-slate-900"
      }`}
    >
      {inner}
    </button>
  );
}
