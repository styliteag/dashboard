/**
 * Query/mutation hooks + lookup for entity comments (see CommentBadge.tsx).
 * JSX-free on purpose (Fast Refresh: component files export only components).
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import type { CommentKind, EntityComment } from "./types";

/** All comments of one instance (per-instance tab sections). */
export function useInstanceComments(instanceId: number, enabled = true) {
  return useQuery({
    queryKey: ["comments", instanceId],
    queryFn: () => api.get<EntityComment[]>(`/api/instances/${instanceId}/comments`),
    refetchInterval: 60_000,
    enabled,
  });
}

/** One kind across all visible instances (overview pages). */
export function useAllComments(kind: CommentKind, enabled = true) {
  return useQuery({
    queryKey: ["comments-all", kind],
    queryFn: () => api.get<EntityComment[]>(`/api/comments?kind=${kind}`),
    refetchInterval: 60_000,
    enabled,
  });
}

export interface SetCommentVars {
  instanceId: number;
  kind: CommentKind;
  entityKey: string;
  comment: string; // "" deletes
}

/** Upsert/delete one comment; refreshes both the per-instance and overview caches. */
export function useSetComment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: SetCommentVars) =>
      api.put<{ ok: boolean }>(`/api/instances/${v.instanceId}/comments`, {
        kind: v.kind,
        entity_key: v.entityKey,
        comment: v.comment,
      }),
    onSuccess: (_data, v) => {
      qc.invalidateQueries({ queryKey: ["comments", v.instanceId] });
      qc.invalidateQueries({ queryKey: ["comments-all"] });
    },
  });
}

export function findComment(
  rows: EntityComment[] | undefined,
  instanceId: number,
  kind: CommentKind,
  entityKey: string,
): EntityComment | undefined {
  return rows?.find(
    (r) => r.instance_id === instanceId && r.kind === kind && r.entity_key === entityKey,
  );
}
