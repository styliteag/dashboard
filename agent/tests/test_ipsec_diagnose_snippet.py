"""Per-tunnel scoping + secret redaction for the `ipsec.diagnose` bundle.

Fixtures mirror real OPNsense (`/conf/config.xml` `<Swanctl>`) and pfSense
(`/cf/conf/config.xml` `<ipsec>`) layouts captured on the test lab boxes. The
load-bearing assertion is negative: a pfSense pre-shared key (stored inline in
`<phase1>`) must never survive into the bundle that reaches the AI context.
"""

from xml.etree import ElementTree

import orbit_agent as agent

# --- swanctl --list-conns --raw, two connections (trimmed real VICI stream) ----
_RAW = (
    "list-conn event {5fe62ba0-AAAA "
    "{local_addrs=[10.21.7.100] remote_addrs=[10.21.7.101] version=IKEv2 "
    "proposals {0 {encr=[AES_CBC_256] integ=[HMAC_SHA2_256_128] ke=[MODP_2048]}} "
    "children {C1 {esp_proposals=[AES_GCM_16_256] local-ts=[10.1.1.0/24] "
    "remote-ts=[10.2.2.0/24]}}} "
    "OTHER-BBBB {local_addrs=[10.21.7.100] remote_addrs=[2.2.2.2] "
    "proposals {0 {encr=[AES_CBC_128]}}}}"
)

# --- swanctl --list-conns, plain, with a leading warning + a second tunnel ------
_PLAIN = (
    "no files found matching '/usr/local/etc/strongswan.opnsense.d/*.conf'\n"
    "5fe62ba0-AAAA: IKEv2, no reauthentication, rekeying every 14400s, dpd delay 10s\n"
    "  local:  10.21.7.100[500]\n"
    "  remote: 10.21.7.101[500]\n"
    "  C1: TUNNEL, rekeying every 3600s, dpd action is start\n"
    "    local:  10.1.1.0/24\n"
    "    remote: 10.2.2.0/24\n"
    "OTHER-BBBB: IKEv2, no reauthentication, rekeying every 14400s, dpd delay 10s\n"
    "  local:  10.21.7.100[500]\n"
    "  remote: 2.2.2.2[500]\n"
)

# --- OPNsense config.xml: PSK lives in <preSharedKeys>, never under a Connection -
_OPNSENSE_XML = """<opnsense>
  <OPNsense>
    <Swanctl version="1.0.0">
      <Connections>
        <Connection uuid="5fe62ba0-AAAA">
          <enabled>1</enabled>
          <proposals>default</proposals>
          <local_addrs>10.21.7.100</local_addrs>
          <remote_addrs>10.21.7.101</remote_addrs>
          <dpd_delay>10</dpd_delay>
          <description>opn1-opn2</description>
        </Connection>
        <Connection uuid="OTHER-BBBB">
          <local_addrs>10.21.7.100</local_addrs>
          <remote_addrs>2.2.2.2</remote_addrs>
          <description>other-tunnel</description>
        </Connection>
      </Connections>
      <locals>
        <local uuid="L1"><connection>5fe62ba0-AAAA</connection><auth>psk</auth><id>10.21.7.100</id></local>
        <local uuid="L2"><connection>OTHER-BBBB</connection><auth>psk</auth><id>9.9.9.9</id></local>
      </locals>
      <remotes>
        <remote uuid="R1"><connection>5fe62ba0-AAAA</connection><auth>psk</auth><id>10.21.7.101</id></remote>
      </remotes>
      <children>
        <child uuid="C1"><connection>5fe62ba0-AAAA</connection><esp_proposals>aes256gcm16-sha256</esp_proposals><local_ts>10.1.1.0/24</local_ts><remote_ts>10.2.2.0/24</remote_ts></child>
        <child uuid="C2"><connection>OTHER-BBBB</connection><esp_proposals>aes128-sha1</esp_proposals><local_ts>10.1.1.0/24</local_ts><remote_ts>2.2.2.0/24</remote_ts></child>
      </children>
      <preSharedKeys>
        <PreSharedKey uuid="K1"><Key>OPNSENSE_SECRET_PSK_VALUE</Key><id>10.21.7.100</id></PreSharedKey>
      </preSharedKeys>
    </Swanctl>
  </OPNsense>
</opnsense>
"""

# --- pfSense config.xml: PSK is inline in <phase1>, two tunnels (ikeid 1 + 2) ---
_PFSENSE_XML = """<pfsense>
  <ipsec>
    <phase1>
      <ikeid>1</ikeid>
      <iketype>ikev2</iketype>
      <remote-gateway>10.21.7.100</remote-gateway>
      <encryption>
        <item>
          <encryption-algorithm><name>aes</name><keylen>128</keylen></encryption-algorithm>
          <hash-algorithm>sha256</hash-algorithm>
          <dhgroup>14</dhgroup>
        </item>
      </encryption>
      <pre-shared-key>321647982e8d7689fds7afdsf8dsf</pre-shared-key>
      <private-key></private-key>
      <pkcs11pin></pkcs11pin>
      <descr><![CDATA[pf1-opn1]]></descr>
      <dpd_delay>10</dpd_delay>
    </phase1>
    <phase1>
      <ikeid>2</ikeid>
      <pre-shared-key>SECOND_TUNNEL_SECRET</pre-shared-key>
      <descr><![CDATA[pf1-other]]></descr>
    </phase1>
    <phase2>
      <ikeid>1</ikeid>
      <mode>tunnel</mode>
      <localid><address>10.3.3.0</address><netbits>24</netbits></localid>
      <remoteid><address>10.1.1.0</address><netbits>24</netbits></remoteid>
      <hash-algorithm-option>hmac_sha256</hash-algorithm-option>
      <pfsgroup>14</pfsgroup>
      <descr><![CDATA[pf1-opn1-p2-1]]></descr>
    </phase2>
    <phase2>
      <ikeid>2</ikeid>
      <descr><![CDATA[pf1-other-p2]]></descr>
    </phase2>
  </ipsec>
</pfsense>
"""

_PFSENSE_PSK = "321647982e8d7689fds7afdsf8dsf"


# ---------------------------------------------------------------- raw slice ----
def test_slice_raw_conn_keeps_only_selected_with_proposals() -> None:
    out = agent._slice_raw_conn(_RAW, "5fe62ba0-AAAA")
    assert out.startswith("5fe62ba0-AAAA {")
    assert out.endswith("}")
    assert "AES_GCM_16_256" in out  # this tunnel's child proposal survives
    assert "MODP_2048" in out
    assert "OTHER-BBBB" not in out  # the other tunnel is gone
    assert "2.2.2.2" not in out
    assert "AES_CBC_128" not in out


def test_slice_raw_conn_balanced_braces() -> None:
    out = agent._slice_raw_conn(_RAW, "5fe62ba0-AAAA")
    assert out.count("{") == out.count("}")


def test_slice_raw_conn_absent_returns_empty() -> None:
    assert agent._slice_raw_conn(_RAW, "no-such-conn") == ""


def test_slice_raw_conn_empty_name_does_not_hang() -> None:
    # an empty needle matches at every offset; guard must short-circuit it
    assert agent._slice_raw_conn(_RAW, "") == ""


# -------------------------------------------------------------- plain slice ----
def test_slice_plain_conn_keeps_only_selected_block() -> None:
    out = agent._slice_plain_conn(_PLAIN, "5fe62ba0-AAAA")
    assert out.startswith("5fe62ba0-AAAA: IKEv2")
    assert "10.21.7.101" in out
    assert "C1: TUNNEL" in out
    assert "OTHER-BBBB" not in out  # second tunnel excluded
    assert "2.2.2.2" not in out
    assert "no files found" not in out  # leading warning line dropped


# ------------------------------------------------------ OPNsense config.xml ----
def _write(tmp_path, body: str) -> str:
    p = tmp_path / "config.xml"
    p.write_text(body)
    return str(p)


def test_opnsense_snippet_scopes_to_uuid_and_omits_psk(tmp_path) -> None:
    out = agent._ipsec_config_snippet("5fe62ba0-AAAA", _write(tmp_path, _OPNSENSE_XML))
    assert "opn1-opn2" in out  # the Connection
    assert "aes256gcm16-sha256" in out  # its child esp_proposals
    assert "10.21.7.101" in out  # its remote auth id
    # other tunnel's pieces must not bleed in
    assert "other-tunnel" not in out
    assert "aes128-sha1" not in out
    assert "9.9.9.9" not in out
    # OPNsense PSK lives in <preSharedKeys>, which is never serialized
    assert "OPNSENSE_SECRET_PSK_VALUE" not in out


# ------------------------------------------------------- pfSense config.xml ----
def test_pfsense_snippet_redacts_inline_psk(tmp_path) -> None:
    out = agent._ipsec_config_snippet("con1", _write(tmp_path, _PFSENSE_XML))
    # the load-bearing assertion: the plaintext PSK never leaves the box
    assert _PFSENSE_PSK not in out
    assert "***REDACTED***" in out
    # the diagnostic crypto detail survives (no over-redaction of <keylen>)
    assert "aes" in out
    assert "sha256" in out
    assert "<keylen>128</keylen>" in out
    assert "pf1-opn1" in out  # phase1 descr
    assert "10.3.3.0" in out  # phase2 selector


def test_pfsense_snippet_scopes_to_ikeid(tmp_path) -> None:
    out = agent._ipsec_config_snippet("con1", _write(tmp_path, _PFSENSE_XML))
    assert "pf1-other" not in out  # ikeid 2 phase1 excluded
    assert "pf1-other-p2" not in out  # ikeid 2 phase2 excluded
    assert "SECOND_TUNNEL_SECRET" not in out  # and its PSK never appears


def test_snippet_missing_file_returns_empty() -> None:
    assert agent._ipsec_config_snippet("con1", "/nonexistent/config.xml") == ""


# --------------------------------------------------- _redact_secrets (direct) --
def test_redact_secrets_blanks_opnsense_key_but_keeps_keylen() -> None:
    # Defense-in-depth: even if a <preSharedKeys><Key> ever reached serialization,
    # its text is blanked — while diagnostic <keylen>/<keyingtries> survive.
    elem = ElementTree.fromstring(
        "<root>"
        "<Key>OPNSENSE_SECRET</Key>"
        "<pre-shared-key>PF_SECRET</pre-shared-key>"
        "<keylen>128</keylen>"
        "<keyingtries>3</keyingtries>"
        "<id>10.0.0.1</id>"
        "</root>"
    )
    agent._redact_secrets(elem)
    out = ElementTree.tostring(elem, encoding="unicode")
    assert "OPNSENSE_SECRET" not in out
    assert "PF_SECRET" not in out
    assert out.count("***REDACTED***") == 2
    assert "<keylen>128</keylen>" in out  # not over-redacted
    assert "<keyingtries>3</keyingtries>" in out
    assert "10.0.0.1" in out  # benign id untouched
