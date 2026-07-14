/**
 * Inline operator comments: a speech-bubble icon when a comment exists (full text
 * as tooltip) and a pencil that appears on row hover (rows need the `group`
 * class). Clicking the pencil swaps to an inline input — Enter/blur saves, Esc
 * cancels, saving empty deletes. Clicks never bubble (overview rows navigate).
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { MessageSquare, Pencil } from "lucide-react";
import { useRef, useState } from "react";
import { api, apiErrorText } from "../lib/api";
import { findComment, useAllComments, useInstanceComments, useSetComment } from "../lib/comments";
import type { CommentKind, Instance } from "../lib/types";

export default function CommentBadge({
  text,
  tooltipSuffix,
  onSave,
  error,
}: {
  text: string | null | undefined;
  tooltipSuffix?: string;
  onSave: (next: string) => void;
  error?: string | null;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const cancelled = useRef(false);

  const commit = (value: string) => {
    setEditing(false);
    if (value.trim() !== (text ?? "").trim()) onSave(value.trim());
  };

  if (editing) {
    return (
      <textarea
        autoFocus
        value={draft}
        rows={3}
        onFocus={(e) => {
          // Caret at the end, not the start, when editing an existing comment.
          const n = e.currentTarget.value.length;
          e.currentTarget.setSelectionRange(n, n);
        }}
        onChange={(e) => setDraft(e.target.value)}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          // Multiline: plain Enter inserts a newline; Ctrl/Cmd+Enter (or blur) saves.
          if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) commit(draft);
          if (e.key === "Escape") {
            cancelled.current = true;
            setEditing(false);
          }
        }}
        onBlur={() => {
          if (!cancelled.current) commit(draft);
          cancelled.current = false;
        }}
        placeholder="Comment… (Ctrl+Enter to save, Esc to cancel)"
        maxLength={2000}
        className="w-56 resize-y rounded border border-slate-700 bg-slate-900 px-1.5 py-1 text-xs leading-snug text-slate-200 outline-none focus:border-emerald-600"
      />
    );
  }

  return (
    <span className="inline-flex items-center gap-0.5 align-middle">
      {error ? (
        <MessageSquare className="h-3.5 w-3.5 shrink-0 text-red-400" aria-label={error} />
      ) : (
        text && <MessageSquare className="h-3.5 w-3.5 shrink-0 text-sky-300" aria-label="Comment" />
      )}
      <button
        onClick={(e) => {
          e.stopPropagation();
          setDraft(text ?? "");
          setEditing(true);
        }}
        title={
          error ?? (text ? `${text}${tooltipSuffix ? ` — ${tooltipSuffix}` : ""}` : "Add comment")
        }
        className={`shrink-0 rounded p-0.5 text-slate-500 transition-opacity hover:bg-slate-700 hover:text-slate-200 focus:opacity-100 ${
          text || error ? "" : "opacity-0 group-hover:opacity-100"
        }`}
      >
        <Pencil className="h-3 w-3" />
      </button>
    </span>
  );
}

/**
 * Comment badge bound to one entity — looks the comment up and saves it through
 * the comments API. `scope="instance"` reads the per-instance query (tab
 * sections); `scope="all"` the per-kind overview query (overview pages, one
 * fetch shared by every row via the query cache).
 */
export function EntityCommentBadge({
  instanceId,
  kind,
  entityKey,
  scope,
}: {
  instanceId: number;
  kind: CommentKind;
  entityKey: string;
  scope: "instance" | "all";
}) {
  const perInstance = useInstanceComments(instanceId, scope === "instance");
  const all = useAllComments(kind, scope === "all");
  const set = useSetComment();
  const rows = scope === "instance" ? perInstance.data : all.data;
  const existing = findComment(rows, instanceId, kind, entityKey);
  return (
    <CommentBadge
      text={existing?.comment}
      tooltipSuffix={existing ? `by ${existing.updated_by}` : undefined}
      error={set.isError ? apiErrorText(set.error, "saving comment failed") : null}
      onSave={(next) => set.mutate({ instanceId, kind, entityKey, comment: next })}
    />
  );
}

/** Same badge for the instance's own free-text notes (Instance.notes, PATCH). */
export function InstanceNotesBadge({ inst }: { inst: Instance }) {
  const qc = useQueryClient();
  const save = useMutation({
    mutationFn: (notes: string) => api.patch(`/api/instances/${inst.id}`, { notes: notes || null }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["instances"] });
      qc.invalidateQueries({ queryKey: ["instance", inst.id] });
    },
  });
  return (
    <CommentBadge
      text={inst.notes}
      error={save.isError ? apiErrorText(save.error, "saving comment failed") : null}
      onSave={(next) => save.mutate(next)}
    />
  );
}
