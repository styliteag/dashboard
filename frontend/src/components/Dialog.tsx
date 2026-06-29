/**
 * Minimal modal overlay. No dependencies beyond React.
 */
import { useEffect, type ReactNode } from "react";
import { X } from "lucide-react";

type Size = "md" | "lg" | "xl" | "2xl";

interface Props {
  title: string;
  onClose: () => void;
  children: ReactNode;
  /** @deprecated use size="lg" */
  wide?: boolean;
  size?: Size;
}

const WIDTH: Record<Size, string> = {
  md: "max-w-md",
  lg: "max-w-lg",
  xl: "max-w-3xl",
  "2xl": "max-w-6xl",
};

export default function Dialog({ title, onClose, children, wide, size }: Props) {
  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  const width = WIDTH[size ?? (wide ? "lg" : "md")];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div
        className={`flex max-h-[90vh] w-full flex-col rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl ${width}`}
      >
        <div className="flex shrink-0 items-center justify-between">
          <h2 className="text-lg font-semibold">{title}</h2>
          <button
            onClick={onClose}
            className="rounded-md p-1 text-slate-500 hover:bg-slate-800 hover:text-slate-300"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        {/* min-h-0 lets a flex child own its own scroll instead of growing the modal */}
        <div className="mt-4 flex min-h-0 flex-1 flex-col overflow-auto">{children}</div>
      </div>
    </div>
  );
}
