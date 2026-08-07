# Dataviz-Sprache (D-4/D-9 systemisch) — PRD & Design Record

Status: **Entwurf zum Abnicken** (2026-08-07). Sprache Deutsch wie die
anderen Design Records; Code/UI bleiben Englisch.

## Problem

Die Grundlagen sind seit d6283f9/9ab4a2b da (Charts mit echter y-Achse
und Theme-Serienfarben; Lanes mit Hatch/Legende/Dim). Aber jede Fläche
baut ihr Markup selbst: das Lane-Markup existiert 4× (Availability,
VPN-Fleet, Connectivity-Fleet, History-Dialoge), Balken (ZFS-Kapazität,
Memory) sind Insellösungen, Sparklines gibt es gar nicht, und die
Regeln ("kein Wert" ist grau und niemals 0; jede Schwelle, die eine
Farbe kippt, steht dran; keine Achse ohne Beschriftung) leben nur in
Commit-Messages statt in Komponenten.

## Kernentscheidungen

- **DR-DV1 — Drei geteilte Komponenten**, alle in einem neuen
  `OrbitWeb.Components.Viz` (ListKit-Muster):
  - `<.timeline_lane segments= live_state= …>` — DAS Lane-Markup
    (Segmente, Hatch-Klassen, Dim-Regel, sr-only-Labels, Klick-Target).
    Die 4 bestehenden Flächen migrieren seitenweise darauf; lane_color/
    lane_legend ziehen aus dem TunnelHistoryDialog dorthin um.
  - `<.sparkline points= …>` — nacktes SVG-Polyline (fixe Höhe ~24px,
    keine Achsen, Theme-Serienfarbe, letzter Punkt betont, "no data" =
    grauer Strich). Erster Abnehmer: die expandierte Connectivity-Zeile
    (Punkte liegen dort schon geladen). Die Grid-Card bekommt erst dann
    eine, wenn ein billiger Datenpfad existiert (der Hub-Cache hält nur
    den Momentanwert) — DR-DV3 gilt, die Komponente lädt nie selbst.
  - `<.proportion_bar value= max= warn_at= …>` — der Kapazitäts-/
    Speicherbalken (ZFS, Memory, Disk): Schwellen-Tint + beschriftete
    Schwelle im Tooltip. Ersetzt die ZFS-`bar/1` und die Disk-Balken.
- **DR-DV2 — Regeln wandern in die Komponenten, nicht in ein Doc.**
  Absenz: `nil`/leer rendert die graue Absenz-Form der Komponente,
  niemals 0 oder leere Fläche. Schwellen: eine Farbe kippt nur, wenn
  die Komponente die Schwelle auch nennt (Attribut ist Pflicht, D-6-
  Lektion). Achsen: `metric_chart` bleibt die einzige Achsen-Fläche;
  sparkline/lane sind bewusst achsenfrei.
- **DR-DV3 — Keine neuen Datenpfade.** Alles rendert aus Daten, die die
  Seiten heute schon halten (Hub-Cache, geladene Chart-Punkte, Lanes).
  Wo eine Sparkline neue Reads bräuchte, gibt es sie erst mal nicht.
- **DR-DV4 — Migration seitenweise** (shared-tree-Regel): Komponente +
  Test zuerst, dann pro Commit eine Fläche. Pro (ZFS-Tab) migriert
  seine Balken danach über den normalen Merge.

## Aufwand

Komponenten + Tests ~1 Tag; Migration der 4 Lane-Flächen + Balken ~1
Tag; Sparkline-Abnehmer (Grid-Card, Connectivity) ~½ Tag.

## Offene Fragen an den Betreiber

1. Sparkline in der Grid-Card: CPU-Verlauf oder RTT? (Vorschlag: CPU —
   liegt im Hub-Cache-Umfeld, RTT ist connectivity-spezifisch.)
2. Reicht der Tooltip zur Schwellen-Nennung am Balken, oder Textzeile
   wie beim ARC-Gauge?
