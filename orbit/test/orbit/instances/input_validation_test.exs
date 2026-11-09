defmodule Orbit.Instances.InputValidationTest do
  @moduledoc """
  Server-side validation of the instance create/edit forms — the UI hints in
  `InstanceForm` are advisory only, a crafted LiveView event skips them.

  The sharpest case: pointing `base_url` at another host while the stored API
  key/secret stay put would make the next poll (or "Test connection") hand
  those credentials to that host. A changed origin therefore drops every
  stored API secret that is not re-entered in the same save.
  """
  use Orbit.DataCase, async: false

  alias Orbit.Instances

  @pem """
  -----BEGIN CERTIFICATE-----
  MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
  DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
  EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
  7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
  5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
  BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
  NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
  Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
  6MF9+Yw1Yy0t
  -----END CERTIFICATE-----
  """

  setup do
    group =
      Repo.insert!(%Orbit.Accounts.Group{name: "inval-#{System.unique_integer([:positive])}"})

    {:ok, inst} =
      Instances.create_instance(
        %{
          "name" => "inval-#{System.unique_integer([:positive])}",
          "device_type" => "opnsense",
          "transport" => "direct",
          "base_url" => "https://10.0.0.1",
          "api_key" => "real-key",
          "api_secret" => "real-secret"
        },
        group.id
      )

    {:ok, group_id: group.id, inst: inst}
  end

  defp secrets(inst) do
    inst = Repo.get!(Orbit.Instances.Instance, inst.id)
    {Orbit.Crypto.decrypt!(inst.api_key_enc), Orbit.Crypto.decrypt!(inst.api_secret_enc)}
  end

  describe "base_url origin change" do
    test "a new host without re-entered credentials drops the stored ones", %{inst: inst} do
      assert {:ok, _} = Instances.update_instance(inst, %{"base_url" => "https://evil.example"})
      {key, secret} = secrets(inst)
      refute key == "real-key"
      refute secret == "real-secret"
    end

    test "a new port or scheme counts as a new origin", %{inst: inst} do
      assert {:ok, _} = Instances.update_instance(inst, %{"base_url" => "https://10.0.0.1:8443"})
      assert {k, _} = secrets(inst)
      refute k == "real-key"
    end

    test "comma-separated failover URLs: dropping one keeps, adding one drops", %{inst: inst} do
      assert {:ok, inst} = Instances.update_instance(inst, %{"base_url" => "https://10.0.0.1"})

      assert {:ok, _} =
               Instances.update_instance(inst, %{
                 "base_url" => "https://10.0.0.1, https://fw.example:4444",
                 "api_key" => "k3",
                 "api_secret" => "s3"
               })

      inst = Repo.get!(Orbit.Instances.Instance, inst.id)

      assert {:ok, inst} =
               Instances.update_instance(inst, %{"base_url" => "https://fw.example:4444"})

      assert secrets(inst) == {"k3", "s3"}

      assert {:ok, _} =
               Instances.update_instance(inst, %{
                 "base_url" => "https://fw.example:4444,https://x.example"
               })

      refute secrets(inst) == {"k3", "s3"}
    end

    test "re-entered credentials are kept with the new host", %{inst: inst} do
      assert {:ok, _} =
               Instances.update_instance(inst, %{
                 "base_url" => "https://10.0.0.2",
                 "api_key" => "k2",
                 "api_secret" => "s2"
               })

      assert secrets(inst) == {"k2", "s2"}
    end

    test "same origin (path, case, default port) keeps the stored credentials", %{inst: inst} do
      assert {:ok, _} =
               Instances.update_instance(inst, %{"base_url" => "HTTPS://10.0.0.1:443/api"})

      assert secrets(inst) == {"real-key", "real-secret"}
    end
  end

  describe "url format" do
    test "base_url must be http(s) with a host", %{inst: inst, group_id: gid} do
      for bad <- ["ftp://x", "javascript:alert(1)", "https://", "10.0.0.1", "https://a b"] do
        assert {:error, :bad_base_url} = Instances.update_instance(inst, %{"base_url" => bad}),
               bad

        assert {:error, :bad_base_url} =
                 Instances.create_instance(
                   %{
                     "name" => "x#{System.unique_integer([:positive])}",
                     "device_type" => "opnsense",
                     "base_url" => bad
                   },
                   gid
                 )
      end
    end

    test "ping_url is an http(s) URL or a plain host[:port]", %{inst: inst} do
      for ok <- ["https://10.0.0.1:4444", "fw.example.net", "10.0.0.1", "fw.example.net:443", ""],
          do: assert({:ok, _} = Instances.update_instance(inst, %{"ping_url" => ok}), ok)

      for bad <- ["-f", "ftp://x", "a;b", "https://"],
          do:
            assert(
              {:error, :bad_ping_url} = Instances.update_instance(inst, %{"ping_url" => bad}),
              bad
            )
    end
  end

  describe "ca_bundle" do
    test "a PEM certificate is accepted, garbage refused", %{inst: inst} do
      assert {:ok, _} = Instances.update_instance(inst, %{"ca_bundle" => @pem})

      assert {:error, :bad_ca_bundle} =
               Instances.update_instance(inst, %{"ca_bundle" => "not a pem"})
    end
  end

  describe "numbers and types" do
    test "ssh_port must be 1..65535", %{inst: inst} do
      for bad <- ["0", "65536", "abc", "22;id"],
          do:
            assert(
              {:error, :bad_ssh_port} = Instances.update_instance(inst, %{"ssh_port" => bad})
            )

      assert {:ok, %{ssh_port: 2222}} = Instances.update_instance(inst, %{"ssh_port" => "2222"})
    end

    test "intervals are blank or 5..86400 seconds", %{inst: inst} do
      for bad <- ["1", "86401", "x"],
          do:
            assert(
              {:error, :bad_interval} =
                Instances.update_instance(inst, %{"push_interval_seconds" => bad})
            )

      assert {:ok, %{poll_interval_seconds: 60}} =
               Instances.update_instance(inst, %{"poll_interval_seconds" => "60"})

      assert {:ok, %{poll_interval_seconds: nil}} =
               Instances.update_instance(inst, %{"poll_interval_seconds" => ""})
    end

    test "integer values get the same range checks as strings", %{inst: inst} do
      for bad <- [0, 65_536, -22],
          do:
            assert(
              {:error, :bad_ssh_port} = Instances.update_instance(inst, %{"ssh_port" => bad})
            )

      for bad <- [1, 86_401, -60],
          do:
            assert(
              {:error, :bad_interval} =
                Instances.update_instance(inst, %{"poll_interval_seconds" => bad})
            )

      assert {:ok, %{ssh_port: 2222}} = Instances.update_instance(inst, %{"ssh_port" => 2222})
    end

    test "integers in text fields are refused, not crashed on", %{inst: inst} do
      for key <- ["base_url", "ping_url", "ca_bundle", "name"],
          do: assert({:error, :bad_params} = Instances.update_instance(inst, %{key => 1}), key)
    end

    test "non-string field values are refused, not crashed on", %{inst: inst} do
      assert {:error, :bad_params} = Instances.update_instance(inst, %{"location" => %{"a" => 1}})
      assert {:error, :bad_params} = Instances.update_instance(inst, %{"name" => ["x"]})
    end

    test "overlong text fields are refused", %{inst: inst} do
      assert {:error, :bad_params} =
               Instances.update_instance(inst, %{"location" => String.duplicate("a", 256)})
    end
  end
end
