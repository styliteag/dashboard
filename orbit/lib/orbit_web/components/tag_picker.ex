defmodule OrbitWeb.Components.TagPicker do
  @moduledoc """
  Tag picker with autocomplete — port of the retired TagsInput.tsx: chips for
  the picked tags, a dropdown of tags already in use across the fleet (typed
  text filters it) and a "Create …" entry for a brand-new one.

  The host LiveView holds the state — `init/3` puts it in the assigns, a single
  `handle_event("tag_" <> _, …)` clause forwards to `on_event/3`, and
  `submitted_tags/1` turns it into the form value. State lives in the host, not
  in a LiveComponent, on purpose: the create form re-renders on a rejected
  submit (name collision) and picked chips must survive that, which a
  component re-seeded from its parent's assigns would not.

  Text typed but not committed is NOT lost on submit: the host tracks it in
  `query` (every keystroke arrives via phx-keyup) and folds it into the tags
  when the form is submitted. That replaced an earlier blur-commit, which
  fired on focus changes nobody made — observed live: with a chip already
  picked, a single keystroke turned into a chip of its own.

  The suggestion list must come from `Instances.known_tags(principal)` — tags
  hold customer names, so an unscoped list would leak them to a user who
  cannot see the boxes wearing them (invariant 1).

  The committed value rides a hidden input as a comma-separated string, which
  is what `Instances.coerce(:tags, …)` already parses on both the create and
  the update path — no second server-side spelling of tags.

  Keyboard handling needs the `TagPicker` hook (assets/js/app.js): the filter
  input sits inside the surrounding form, so Enter and "," must be swallowed
  before they submit it.
  """

  use Phoenix.Component

  import OrbitWeb.CoreComponents, only: [icon: 1]

  alias Phoenix.LiveView

  # Enough to pick from without turning into a scroll list — the fleet's tag
  # vocabulary is small, and typing narrows it.
  @max_options 8

  attr :tags, :list, required: true, doc: "committed tags, in order"
  attr :known, :list, required: true, doc: "tags in use across visible instances"
  attr :query, :string, default: "", doc: "text typed into the filter input"
  attr :open, :boolean, default: false, doc: "dropdown visibility"
  attr :name, :string, default: "instance[tags]", doc: "hidden input's form name"

  def tag_picker(assigns) do
    assigns = assign(assigns, :options, options(assigns.known, assigns.tags, assigns.query))

    ~H"""
    <div id="tag-picker" phx-hook="TagPicker" class="block text-sm md:col-span-2">
      <span class="mb-1 block text-xs text-base-content/60">Tags</span>
      <input type="hidden" name={@name} value={Enum.join(@tags, ",")} />
      <div class="relative">
        <div class="flex flex-wrap items-center gap-1 rounded border border-base-content/20 bg-base-100 px-2 py-1 focus-within:border-primary">
          <span
            :for={tag <- @tags}
            class="flex items-center gap-1 rounded bg-base-300 px-2 py-0.5 text-xs text-base-content"
          >
            {tag}
            <button
              type="button"
              phx-click="tag_remove"
              phx-value-tag={tag}
              aria-label={"Remove tag #{tag}"}
              class="text-base-content/60 hover:text-base-content"
            >
              <.icon name="hero-x-mark" class="size-3" />
            </button>
          </span>
          <%!-- Deliberately NAMELESS and without a `value`, both learned by
               watching this run in a browser. A `name` makes LiveView treat
               it as a form input and reset it to the server-rendered value on
               every patch — each keystroke was wiped as it was typed. Its
               text reaches the server through phx-keyup instead (the host
               keeps it in `tag_query` and folds it in on submit), and the
               hook clears it on a "tag_picker_clear" push. --%>
          <input
            type="text"
            id="tag-picker-input"
            autocomplete="off"
            phx-keyup="tag_key"
            phx-focus="tag_focus"
            phx-blur="tag_close"
            placeholder={if @tags == [], do: "type to search or create…"}
            class="min-w-24 flex-1 bg-transparent py-0.5 text-sm text-base-content focus:outline-none"
          />
        </div>
        <ul
          :if={@open and @options != []}
          class="absolute z-10 mt-1 max-h-48 w-full overflow-y-auto rounded border border-base-content/20 bg-base-100 py-1 text-sm shadow-lg"
        >
          <li :for={{kind, tag} <- @options}>
            <button
              type="button"
              data-tag-option
              phx-click="tag_add"
              phx-value-tag={tag}
              class="block w-full px-3 py-1.5 text-left text-base-content/80 hover:bg-base-300 hover:text-base-content"
            >
              <span :if={kind == :create}>
                Create <span class="font-medium text-primary">“{tag}”</span>
              </span>
              <span :if={kind == :existing}>{tag}</span>
            </button>
          </li>
        </ul>
      </div>
    </div>
    """
  end

  @doc """
  Seed the picker's assigns. Call once in the host's `mount/3`.
  """
  @spec init(LiveView.Socket.t(), [String.t()], [String.t()]) :: LiveView.Socket.t()
  def init(socket, tags, known) do
    assign(socket, tags: tags || [], known_tags: known, tag_query: "", tag_open: false)
  end

  @doc """
  Apply one `tag_*` event to the host's socket.

  Both forms forward every `tag_` event here, so the picker behaves identically
  on create and edit and a fix lands in one place. Enter and "," commit the
  typed text (the hook keeps them from submitting the surrounding form),
  Escape and blur only close the dropdown, Backspace either clears typed text
  or eats the last chip — see `backspace/2` for why that needs the previous
  query rather than the payload.
  """
  @spec on_event(String.t(), map(), LiveView.Socket.t()) :: LiveView.Socket.t()
  def on_event("tag_key", %{"key" => key, "value" => value}, socket) do
    case key do
      k when k in ["Enter", ","] ->
        commit(socket, value)

      "Escape" ->
        assign(socket, tag_open: false)

      "Backspace" ->
        assign(socket,
          tags: backspace(socket.assigns.tags, socket.assigns.tag_query),
          tag_query: value,
          tag_open: true
        )

      _ ->
        assign(socket, tag_query: value, tag_open: true)
    end
  end

  def on_event("tag_add", %{"tag" => tag}, socket), do: commit(socket, tag)

  def on_event("tag_remove", %{"tag" => tag}, socket) do
    assign(socket, tags: remove(socket.assigns.tags, tag))
  end

  def on_event("tag_focus", _params, socket), do: assign(socket, tag_open: true)

  # Closing only — never committing. A blur commit fired on focus changes
  # nobody made (a lone keystroke became a chip, seen in the browser); the
  # typed leftover is folded in at submit time instead.
  def on_event("tag_close", _params, socket), do: assign(socket, tag_open: false)

  defp commit(socket, text) do
    socket
    |> assign(
      tags: add(socket.assigns.tags, text, socket.assigns.known_tags),
      tag_query: ""
    )
    |> LiveView.push_event("tag_picker_clear", %{})
  end

  @doc """
  The form value: picked chips plus whatever sits half-typed in the filter
  field, comma-separated for `Instances.coerce(:tags, …)`.

  Submitting with text still in the field is a normal way to fill a form —
  that tag counts. The text comes from the assigns, not the form params: the
  filter input carries no form name (a named input is reset to the
  server-rendered value on every patch, which wiped each keystroke as it was
  typed), so phx-keyup is what the server knows it by.
  """
  @spec submitted_tags(LiveView.Socket.t()) :: String.t()
  def submitted_tags(socket) do
    socket.assigns.tags
    |> add(socket.assigns.tag_query, socket.assigns.known_tags)
    |> Enum.join(",")
  end

  @doc """
  Append a typed tag. Blank input and a tag already picked are no-ops.

  Case is normalised twice over, because the fleet page filters tags on exact
  matches and a near-miss spelling is invisible until someone wonders why a
  filter chip is missing boxes: the duplicate guard is case-insensitive, and
  typing an existing tag in another case adopts the fleet's spelling
  (typing "lab" where the fleet says "LAB" picks "LAB", not a second tag).
  """
  @spec add([String.t()], String.t(), [String.t()]) :: [String.t()]
  def add(tags, text, known \\ []) do
    clean = String.trim(text)
    lower = String.downcase(clean)
    taken = MapSet.new(tags, &String.downcase/1)

    cond do
      clean == "" -> tags
      MapSet.member?(taken, lower) -> tags
      true -> tags ++ [Enum.find(known, clean, &(String.downcase(&1) == lower))]
    end
  end

  @doc "Remove a chip by exact value."
  @spec remove([String.t()], String.t()) :: [String.t()]
  def remove(tags, tag), do: Enum.reject(tags, &(&1 == tag))

  @doc "Backspace on an empty filter input eats the last chip."
  @spec drop_last([String.t()]) :: [String.t()]
  def drop_last([]), do: []
  def drop_last(tags), do: Enum.drop(tags, -1)

  @doc """
  Chips after a Backspace, decided on the query as it was BEFORE the keystroke.

  phx-keyup reports the value the field has once the key has done its work, so
  deleting the last character of typed text and pressing Backspace in an
  already-empty field both arrive as `value: ""`. Reading only that, clearing
  a half-typed tag would eat the chip in front of it — the previous query is
  what tells the two apart.
  """
  @spec backspace([String.t()], String.t()) :: [String.t()]
  def backspace(tags, ""), do: drop_last(tags)
  def backspace(tags, _previous_query), do: tags

  @doc """
  Dropdown entries for the typed text: known tags not already picked, filtered
  by substring, plus a `:create` entry when the text matches no known tag.
  """
  @spec options([String.t()], [String.t()], String.t()) :: [{:existing | :create, String.t()}]
  def options(known, tags, query) do
    typed = String.trim(query)
    lower = String.downcase(typed)
    taken = MapSet.new(tags, &String.downcase/1)

    matches =
      known
      |> Enum.reject(&MapSet.member?(taken, String.downcase(&1)))
      |> Enum.filter(&(lower == "" or String.contains?(String.downcase(&1), lower)))
      |> Enum.take(@max_options)
      |> Enum.map(&{:existing, &1})

    creatable? =
      lower != "" and not MapSet.member?(taken, lower) and
        not Enum.any?(known, &(String.downcase(&1) == lower))

    if creatable?, do: matches ++ [{:create, typed}], else: matches
  end
end
