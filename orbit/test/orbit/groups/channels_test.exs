defmodule Orbit.Groups.ChannelsTest do
  @moduledoc """
  Group-channel config validation + masking (groups/channels.py parity).
  Pure functions only — the thin SQL upsert/delete wrappers stay untested
  (house style); the notifier-side overlay is covered in notifier_test.
  """
  use ExUnit.Case, async: true

  alias Orbit.Groups.Channels

  @mask Channels.mask()

  describe "validate/4" do
    test "unknown fields are rejected" do
      assert {:error, "unknown fields: bogus"} =
               Channels.validate("telegram", %{"bogus" => "x"}, %{})
    end

    test "required fields must end up non-empty" do
      assert {:error, "field 'token' is required"} =
               Channels.validate("telegram", %{"chat_id" => "42"}, %{})
    end

    test "a secret sent as the mask keeps the stored value" do
      assert {:ok, %{"token" => "stored", "chat_id" => "42"}} =
               Channels.validate(
                 "telegram",
                 %{"token" => @mask, "chat_id" => "42"},
                 %{"token" => "stored"}
               )
    end

    test "the mask with nothing stored fails required, never saves the mask" do
      assert {:error, "field 'token' is required"} =
               Channels.validate("telegram", %{"token" => @mask, "chat_id" => "42"}, %{})
    end

    test "email: security enum + smtp_port bounds" do
      base = %{"smtp_host" => "h", "from" => "a@b", "to" => "c@d"}

      assert {:error, "field 'security' must be one of starttls, ssl, none"} =
               Channels.validate("email", Map.put(base, "security", "tls"), %{})

      assert {:error, "invalid smtp_port"} =
               Channels.validate("email", Map.put(base, "smtp_port", "99999"), %{})

      assert {:ok, config} = Channels.validate("email", Map.put(base, "smtp_port", "465"), %{})
      assert config["smtp_port"] == "465"
    end

    test "mattermost url is ssrf-checked at save time" do
      assert {:error, "URL rejected: nope"} =
               Channels.validate("mattermost", %{"url" => "https://x"}, %{},
                 ssrf_check: fn _ -> "nope" end
               )

      assert {:ok, %{"url" => "https://x"}} =
               Channels.validate("mattermost", %{"url" => "https://x"}, %{},
                 ssrf_check: fn _ -> nil end
               )
    end
  end

  describe "masked/2" do
    test "secrets mask, non-secrets pass, empty secrets stay empty" do
      masked =
        Channels.masked("email", %{
          "smtp_host" => "smtp.example.com",
          "password" => "hunter2",
          "username" => ""
        })

      assert masked == %{
               "smtp_host" => "smtp.example.com",
               "password" => @mask,
               "username" => ""
             }
    end

    test "stored keys outside the spec are dropped" do
      assert Channels.masked("mattermost", %{"url" => "u", "junk" => "x"}) == %{"url" => @mask}
    end
  end
end
