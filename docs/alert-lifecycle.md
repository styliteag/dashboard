# Alert-Lifecycle (E4 / U-M3) — PRD & Design Record

Status: **Entwurf zum Abnicken** (2026-08-07). Sprache Deutsch wie die
anderen Design Records; Code/UI bleiben Englisch.

## Problem

Die Alerts-Seite ist eine reine Leseliste: jeder Render berechnet die
non-OK-Checks frisch (`Orbit.Checks.Export.evaluated`), nichts wird
festgehalten. Konsequenz um 3 Uhr nachts: kein "seit wann?", kein "hab
ich gesehen", kein "bis morgen früh ruhig", und ein 40-Zeilen-Gewitter
einer flatternden Box sieht aus wie 40 neue Probleme (U-M3).

## Kernentscheidungen

- **DR-LC1 — Identität.** Ein Alert ist `(instance_id, check_key)`. Der
  check_key ist bereits stabil (`family:stable-id`, DB-Ids, nie Namen) —
  genau dafür wurde er so gebaut.
- **DR-LC2 — Persistenz + Reconciler.** Neue Tabelle `alert_states`:
  `instance_id, check_key, severity, first_seen_at, last_seen_at,
  acked_by, acked_at, snoozed_until, resolved_at` (+ ts-Index, batched
  pruning wie üblich). Ein Reconciler im 30s-Tier gleicht die berechneten
  non-OK-Checks gegen die Tabelle ab: neu → insert (first_seen), noch da
  → last_seen touch + severity update, verschwunden → resolved_at setzen
  (Row bleibt für die Historie, Prune nach Retention). Läuft intern
  (None-Principal-Äquivalent, unscoped) — die UI scoped beim Lesen.
- **DR-LC3 — Exporte bleiben unberührt.** Ack/Snooze wirkt NUR auf der
  Alerts-Seite. Checkmk/Prometheus/Checks-Tab zeigen weiter exakt die
  berechneten Zustände (Vier-Flächen-Parität ist Gesetz; Checkmk hat sein
  eigenes Ack). Ein gesnoozter CRIT ist im Export weiter CRIT.
- **DR-LC4 — Semantik.** *Ack* = "gesehen": Zeile bleibt, dezent
  markiert, zählt nicht mehr in den "neu"-Begriff. Ack erlischt beim
  Resolve (ein WIEDER auftauchender Alert ist wieder un-acked — neuer
  Vorfall). *Snooze* = "bis <Zeitpunkt> aus der Default-Ansicht"
  (1h / 8h / 24h / 7d); ein Severity-ANSTIEG (WARN→CRIT) bricht den
  Snooze. Beides schreibt Audit (`alert.ack`, `alert.snooze`) mit
  check_key im allowlisted Detail.
- **DR-LC5 — UI.** Age-Spalte ("seit 4h", ts_rel + Tooltip absolut,
  sortierbar — Default bleibt worst-first); Ack je Zeile + "Ack visible"
  bulk; Snooze-Dropdown je Zeile; Filter-Chips "active / acked /
  snoozed" mit Default **active** — und weil das ein Vorfilter ist,
  MIT filter_notice (U-Q1-Disziplin). Write-Role-gated (`require_write`-
  Äquivalent im LiveView, never trust hidden UI).
- **DR-LC6 — Später, bewusst NICHT jetzt.** Gruppierung wiederholter
  Check-Familien, Notification-Dedupe über first_seen, Ack-Kommentare.

## Aufwand

Migration + Reconciler + Tests ~1 Tag, UI ~1 Tag, Live-Verifikation am
Lab (Alert erzeugen via Monitor-Fail, ack/snooze/resolve-Zyklus) ~½ Tag.

## Offene Fragen an den Betreiber

1. Snooze-Stufen ok (1h/8h/24h/7d)? Freie Eingabe nötig?
2. Darf ein view_only-User acken? (Vorschlag: nein, write-Rolle.)
3. Retention resolvter Alerts (Vorschlag: 90 Tage, Setting).
