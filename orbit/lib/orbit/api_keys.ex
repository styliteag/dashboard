defmodule Orbit.ApiKeys do
  @moduledoc """
  Machine api-key management — port of apikeys/routes.py + auth/apikey.py.
  Keys are read-only by construction; scoping semantics are change-frozen
  (invariant 1): a key WITHOUT bindings is GLOBAL, so minting/binding is
  privilege-sensitive:

  - A group-scoped admin MUST bind a new key to ≥1 of his own groups (an
    unbound key would read the whole fleet); only a superadmin may mint
    global keys.
  - Reveal: superadmin any key; admin only keys bound WITHIN his groups —
    a global key's token would bypass his instance scoping. Missing /
    revoked / non-revealable / out-of-binding all answer the same nil
    (no oracle).
  - Revoke is soft (stamps revoked_at, DROPS the recoverable copy); purge
    hard-deletes and requires a prior revoke.

  Only the sha256 hash is stored; the full token is returned exactly once
  at creation (and via reveal when explicitly minted revealable — then a
  fernet copy exists until revoke).
  """

  import Ecto.Query

  alias Orbit.Accounts.User
  alias Orbit.Repo

  @prefix "orbit_"

  @doc "Mint a token: {full_token, sha256_hex, display_prefix}."
  def generate_key do
    token = @prefix <> Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    {token, hash_key(token), String.slice(token, 0, String.length(@prefix) + 8)}
  end

  def hash_key(token), do: :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)

  @doc "All keys with their bindings, newest first."
  def list do
    keys =
      Repo.query!(
        "SELECT k.id, k.name, k.prefix, k.purpose, k.revealable, k.created_at, " <>
          "k.last_used_at, k.revoked_at FROM api_keys k ORDER BY k.id DESC"
      ).rows

    bindings =
      Repo.query!(
        "SELECT ag.apikey_id, g.id, g.name FROM apikey_groups ag " <>
          "JOIN `groups` g ON g.id = ag.group_id"
      ).rows
      |> Enum.group_by(&hd/1, fn [_, gid, gname] -> %{id: gid, name: gname} end)

    for [id, name, prefix, purpose, revealable, created, last_used, revoked] <- keys do
      %{
        id: id,
        name: name,
        prefix: prefix,
        purpose: purpose,
        revealable: revealable == 1 or revealable == true,
        created_at: created,
        last_used_at: last_used,
        revoked_at: revoked,
        groups: Map.get(bindings, id, [])
      }
    end
  end

  @doc "Create a key; returns {:ok, %{id, token, prefix}} — token shown ONCE."
  def create(params, %User{} = user) do
    name = String.trim(params["name"] || "")
    revealable = params["revealable"] in [true, "true", "on"]
    purpose = presence(params["purpose"])
    group_ids = params["group_ids"] || []

    with true <- name != "" or {:error, :name_required},
         {:ok, ids} <- resolve_binding(user, group_ids) do
      {token, key_hash, prefix} = generate_key()
      key_enc = if revealable, do: Orbit.Crypto.encrypt(token)

      %{num_rows: 1} =
        Repo.query!(
          "INSERT INTO api_keys (name, key_hash, prefix, revealable, key_enc, purpose, created_at) " <>
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
          [name, key_hash, prefix, revealable, key_enc, purpose, naive_now()]
        )

      [[id]] = Repo.query!("SELECT id FROM api_keys WHERE key_hash = ?", [key_hash]).rows

      for gid <- ids do
        Repo.query!("INSERT IGNORE INTO apikey_groups (apikey_id, group_id) VALUES (?, ?)", [
          id,
          gid
        ])
      end

      {:ok, %{id: id, token: token, prefix: prefix, group_ids: ids}}
    end
  end

  # Non-superadmin: ≥1 binding, all within his groups (an unbound key is
  # GLOBAL — that mint is superadmin-only). Unknown ids refuse the write.
  defp resolve_binding(user, raw_ids) do
    ids =
      raw_ids
      |> Enum.map(fn v ->
        case Integer.parse(to_string(v)) do
          {n, ""} -> n
          _ -> nil
        end
      end)
      |> Enum.uniq()

    memberships = User.group_id_set(user)

    cond do
      Enum.any?(ids, &is_nil/1) ->
        {:error, :unknown_group}

      not user.is_superadmin and ids == [] ->
        {:error, :binding_required}

      not user.is_superadmin and not MapSet.subset?(MapSet.new(ids), memberships) ->
        {:error, :not_a_member}

      ids == [] ->
        {:ok, []}

      true ->
        found =
          Repo.all(from(g in Orbit.Accounts.Group, where: g.id in ^ids, select: g.id))

        if length(found) == length(ids), do: {:ok, ids}, else: {:error, :unknown_group}
    end
  end

  @doc "Soft revoke: stamp + drop the recoverable copy (never revealable again)."
  def revoke(key_id) do
    Repo.query!(
      "UPDATE api_keys SET revoked_at = COALESCE(revoked_at, ?), key_enc = NULL WHERE id = ?",
      [naive_now(), key_id]
    )

    :ok
  end

  @doc "Hard delete — only a revoked key (active keys must be revoked first)."
  def purge(key_id) do
    case Repo.query!("SELECT revoked_at FROM api_keys WHERE id = ?", [key_id]).rows do
      [[nil]] ->
        {:error, :not_revoked}

      [[_]] ->
        Repo.query!("DELETE FROM api_keys WHERE id = ?", [key_id])
        :ok

      [] ->
        :ok
    end
  end

  @doc """
  Full token of a revealable, non-revoked key — nil for missing/revoked/
  non-revealable/out-of-binding alike (no oracle). Callers audit.
  """
  def reveal(key_id, %User{} = user) do
    case Repo.query!(
           "SELECT key_enc, revoked_at, revealable FROM api_keys WHERE id = ?",
           [key_id]
         ).rows do
      [[key_enc, nil, revealable]]
      when key_enc != nil and (revealable == 1 or revealable == true) ->
        if may_reveal?(user, key_id), do: Orbit.Crypto.decrypt!(key_enc)

      _ ->
        nil
    end
  end

  # Superadmin: any key. Admin: only keys whose binding is non-empty AND
  # a subset of his groups (a global key would bypass his scoping).
  defp may_reveal?(%User{is_superadmin: true}, _key_id), do: true

  defp may_reveal?(user, key_id) do
    binding =
      Repo.query!("SELECT group_id FROM apikey_groups WHERE apikey_id = ?", [key_id]).rows
      |> List.flatten()
      |> MapSet.new()

    MapSet.size(binding) > 0 and MapSet.subset?(binding, User.group_id_set(user))
  end

  defp presence(v) do
    case String.trim(to_string(v || "")) do
      "" -> nil
      s -> s
    end
  end

  defp naive_now, do: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_naive()
end
