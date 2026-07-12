import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { X } from "lucide-react";
import { api } from "../lib/api";
import type { Instance } from "../lib/types";

interface Props {
  value: string[];
  onChange: (tags: string[]) => void;
}

interface Option {
  kind: "existing" | "create";
  tag: string;
}

/** Tag picker with autocomplete: chips for selected tags, a dropdown of tags
 * already used across the fleet (typed text filters it), and a "Create" entry
 * for brand-new tags. Enter/comma commit the typed text; Backspace on an empty
 * input removes the last chip. */
export default function TagsInput({ value, onChange }: Props) {
  const [text, setText] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);

  // Known tags across all visible instances — shared cache key, normally
  // already populated by the page that opened the dialog.
  const { data: instances } = useQuery({
    queryKey: ["instances"],
    queryFn: () => api.get<Instance[]>("/api/instances"),
  });
  const known = useMemo(
    () =>
      [...new Set((instances ?? []).flatMap((i) => i.tags ?? []))].sort((a, b) =>
        a.localeCompare(b),
      ),
    [instances],
  );

  const query = text.trim();
  const lower = query.toLowerCase();
  const selectedLower = value.map((t) => t.toLowerCase());
  const matches = known
    .filter((t) => !selectedLower.includes(t.toLowerCase()))
    .filter((t) => !lower || t.toLowerCase().includes(lower))
    .slice(0, 8);
  const canCreate =
    lower !== "" &&
    !selectedLower.includes(lower) &&
    !known.some((t) => t.toLowerCase() === lower);
  const options: Option[] = [
    ...matches.map((tag): Option => ({ kind: "existing", tag })),
    ...(canCreate ? [{ kind: "create", tag: query } as Option] : []),
  ];

  const add = (tag: string) => {
    const clean = tag.trim();
    if (clean === "" || selectedLower.includes(clean.toLowerCase())) return;
    onChange([...value, clean]);
    setText("");
    setActive(-1);
  };
  const remove = (tag: string) => onChange(value.filter((t) => t !== tag));

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      // Never let Enter submit the surrounding form from here.
      e.preventDefault();
      if (active >= 0 && options[active]) add(options[active].tag);
      else add(text);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => (options.length ? (a + 1) % options.length : -1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => (options.length ? (a <= 0 ? options.length - 1 : a - 1) : -1));
    } else if (e.key === "Escape") {
      setOpen(false);
    } else if (e.key === "Backspace" && text === "" && value.length > 0) {
      remove(value[value.length - 1]);
    }
  };

  return (
    <div className="space-y-1">
      <label className="text-xs text-slate-400">Tags</label>
      <div className="relative">
        <div className="flex flex-wrap items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2 py-1.5 focus-within:border-emerald-600 focus-within:ring-1 focus-within:ring-emerald-600">
          {value.map((tag) => (
            <span
              key={tag}
              className="flex items-center gap-1 rounded bg-slate-700 px-2 py-0.5 text-xs text-slate-200"
            >
              {tag}
              <button
                type="button"
                onClick={() => remove(tag)}
                className="text-slate-400 hover:text-slate-100"
                aria-label={`Remove tag ${tag}`}
              >
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
          <input
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setOpen(true);
              setActive(-1);
            }}
            onFocus={() => setOpen(true)}
            // Commit whatever was typed so a click on Save doesn't drop it.
            onBlur={() => {
              setOpen(false);
              add(text);
            }}
            onKeyDown={onKeyDown}
            placeholder={value.length === 0 ? "type to search or create…" : ""}
            className="min-w-24 flex-1 bg-transparent py-0.5 text-sm focus:outline-none"
          />
        </div>
        {open && options.length > 0 && (
          <ul className="absolute z-10 mt-1 max-h-48 w-full overflow-y-auto rounded-lg border border-slate-700 bg-slate-800 py-1 text-sm shadow-lg">
            {options.map((o, i) => (
              <li key={`${o.kind}:${o.tag}`}>
                <button
                  type="button"
                  // onMouseDown so the pick wins over the input's blur.
                  onMouseDown={(e) => {
                    e.preventDefault();
                    add(o.tag);
                  }}
                  onMouseEnter={() => setActive(i)}
                  className={`block w-full px-3 py-1.5 text-left ${
                    i === active ? "bg-slate-700 text-slate-100" : "text-slate-300"
                  }`}
                >
                  {o.kind === "create" ? (
                    <>
                      Create <span className="font-medium text-emerald-400">“{o.tag}”</span>
                    </>
                  ) : (
                    o.tag
                  )}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
