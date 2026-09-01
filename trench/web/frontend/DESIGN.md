> **Revised 2026-07-30.** Three rules in the original version below were
> reversed after the console was reviewed in use, and the text has *not* been
> rewritten around them — the reasoning is left standing so the trade is legible:
>
> 1. **The serif is gone.** Its stack was all locally-installed faces (Iowan,
>    Charter, Palatino), present on one designer's machine and almost nowhere
>    else, so most people saw an arbitrary fallback and the console looked
>    different on every device. Reserving a face for prose also invited prose:
>    every view had grown a three-line essay under its title. Two faces now.
> 2. **Outcome colours are conventional.** "Exactly two hues, and blocking gets
>    a calm indigo because it is deliberate rather than dangerous" is good
>    reasoning that produced an unusable result: blocking is the one thing this
>    product does, and it has to be findable at a glance in a thousand rows.
>    Blocked is red, failed amber, cached green, forwarded blue.
> 3. **Absence is not stated in prose.** A missing control is a missing feature,
>    not a design position. Settings is generated from the config schema and the
>    privacy level is set in the UI; the pages that used to explain why you had
>    to edit a file by hand no longer need to.

# Trench Console — Design Contract ("Bailiwick")

This document is the **binding contract** for anyone (human or AI) adding UI to
this app. Follow it and your work will belong here. Improvise colours, sizes,
type or charts and it will not. **When in doubt, copy `views/Browse.vue`.**

The name is a DNS term — bailiwick checking is refusing records a server has no
authority over — and it also means the area you have jurisdiction over.

> **History.** This replaces the previous contract, "Ledger" (monospace
> everywhere, hairline sections, one hue per DNS outcome). Ledger's instincts
> about surface were right and are kept. Two things it got wrong are not:
> 10–11px monospace for *everything*, which is a legibility failure rather than a
> style, and a hue per outcome, which does not survive being drawn small and
> makes the screen read like a status page. A first attempt at replacing it —
> lanes of every device against time, on a canvas — was built, measured against
> real traffic and **deleted**: at six hours a busy device is uniform noise, so it
> was a heatmap with extra steps. Read §2 before proposing a chart.

## 1. The language

1. **Three faces, three jobs, no overlap.**
   - *Identifiers* — names, addresses, rules, timestamps — are **monospaced,
     always** (`--b-id`, 13px). Mono is reserved for strings you compare
     character by character; the face carries information, not flavour.
   - *Interface* — labels, counts, headings — is the system grotesk
     (`--b-ui`, 13px/500) with `tabular-nums` on, so a column of numbers lines up
     and a changing digit does not make the row twitch.
   - *Explanation* — anything read as a sentence — is a serif (`--b-read`, 15px).
     It separates "the product talking" from "your data", and it reads better in
     paragraphs. Use `.b-read`.

   **Nothing is below 12px.** There is no 10px in this system.
2. **One channel per meaning.** The three ways a query can be answered are one
   ink at three weights (`--o-cache`, `--o-upstream`, `--o-local`) because they
   are the same event at different costs. Exactly two facts get a hue: we
   intervened (`--o-withheld`, indigo — deliberate, not dangerous) and something
   failed (`--o-failed`, ochre). An unrecorded outcome gets **no fill**. "A rule
   you wrote decided this" is a 3px marker in the row margin, never a colour.
3. **One plane.** No cards, no elevation, no shadows except on the single raised
   surface (overlays and menus). Regions are separated by hairlines
   (`--b-edge`, `--b-edge-soft`) and space.
4. **Absence is stated, never illustrated.** Empty means a sentence in serif
   saying what is not there and why (`.b-void-state`). Never "No data yet", never
   an illustration, never sample data. If the interface cannot know something it
   says so — see the `firstIsEdge` guard in `ui/Evidence.vue`.
5. **Every view is a permalink.** Selection, grouping, sort and window all live
   in the URL. A screen an operator cannot send to someone else is half a tool.
6. **Keyboard first.** Every action has a key; focus rings are never removed.
   `?` opens the key sheet, and the sheet is built from the same tables as the
   behaviour so it cannot drift.

## 2. Hard rules (violating any = rejected change)

- **No new dependencies.** Vue + vue-router is the entire runtime. Charts are
  hand-drawn SVG in `src/ui/`.
- **No new colours, sizes or faces.** Everything comes from
  `src/styles/bailiwick.css`. A sixth type size means the hierarchy is wrong.
- **No emoji or typographic symbols standing in for icons.** Icons are drawn in
  `ui/Ico.vue` on a 16px grid, 1.5px stroke, butt caps, geometry only. Add to
  that set; do not import one. The conventional metaphor is not automatically
  right: the grouping control is three bars of decreasing width (levels), not a
  funnel, because nothing is being filtered out; the window control is a caliper,
  not a clock, because it is a measured span and not a moment.
- **Do not reach for the conventional chart.** Each chart here exists because it
  is the best answer for its quantity, and the reasoning is in its file header:
  a spine (`ui/Spine.vue`) carries magnitude *and* composition in one mark so no
  row needs a number plus a donut; the span band (`ui/Span.vue`) puts answers
  above a baseline and refusals below because a stack renders "retrying" and
  "gone quiet" identically; latency (`ui/Percentiles.vue`) is a distribution on a
  **log** axis because a linear axis renders every cache hit as zero.
  **Banned outright:** donuts, gauges, treemaps, sunbursts, KPI tiles,
  big-number-over-tiny-label, and a second time axis anywhere on the primary view.
- **No scoped CSS in views; no inline layout or colour styles** beyond tiny
  one-offs. Recurring patterns go into the stylesheet with a comment.
- **Pure logic stays out of components.** Aggregation, name parsing, outcome
  classification and the query language live in `src/lib/` and are **tested**:
  `node src/lib/facets.test.ts` and `node src/lib/qlang.test.ts` (Node runs the
  TypeScript directly; no test framework is installed and none should be).
  If it has judgement in it, it belongs in `lib/` behind a test.
- **Never inflate a small number into a visible mark.** A spine segment under
  half a pixel is dropped, not rounded up — see `ui/Spine.vue`.
- **Say when the data is partial.** The API caps a page at 1000 rows; `Browse`
  pages to a budget and states the shortfall rather than drawing a subset as
  though it were everything.
- Respect `prefers-reduced-motion`. Motion is limited to 90ms colour
  transitions; nothing moves position and nothing loops.

## 3. Privacy is a design rule, not a feature

Everything in `lib/dnsname.ts` is derived locally. Off-box enrichment is
**declared and never performed**: each entry in `OFF_BOX` states exactly what
would be transmitted and to whom, nothing runs on hover or in a batch, and bulk
datasets (public suffix list, OUI registry, IP-to-ASN) are preferred because
downloading a whole file reveals nothing about what you were curious about. A DNS
console that quietly ships the names its operator resolves to a third party is
doing the exact thing the product exists to prevent.

## 4. File map

```
src/
  main.ts              routes (lazy views; "/" = Browse)
  App.vue              auth gate: login ⇄ Frame
  Frame.vue            the frame: wordmark, place sheet (g), state, skin
  styles/
    bailiwick.css      THE system: tokens, type, every shared class
    tokens.css app.css legacy, kept only for the older views; do not extend
  lib/
    qlang.ts (+test)   the query language: lexer, parser, evaluator,
                       server pushdown, explain(). 82 assertions
    facets.ts (+test)  facet definitions, aggregation, sorting, narrowing,
                       summaries, histogram. 77 assertions
    outcome.ts         the six outcomes and their fills
    dnsname.ts         eTLD+1, boundary alignment, name shape, address class,
                       the off-box declarations
    api.ts store.ts util.ts format.ts
  ui/
    Ico.vue            the drawn icon set
    Spine.vue Span.vue Percentiles.vue   the three charts
    Evidence.vue       selection facts, and the chain for one query
    Palette.vue Inspector.vue Toasts.vue …
  views/
    Browse.vue         the primary surface: faceted column browser
    Pulse QueryLog Explore Rules Collateral Clients Privacy System Audit
    Settings           older views, still on the legacy classes
```

## 5. The primary surface

`Browse.vue` is a browser over one relation. Each column is one level of a
grouping chain; picking a row narrows everything to its right; the operator
chooses the order (`f`). `suffix › domain › name` reads the namespace,
`device › domain › name` reads the network, `list › rule › name` reads your own
policy back to you by its effect. One mechanism, several questions, no separate
screen for each.

Columns rather than a tree or a treemap, and the reasons are not aesthetic: a
column always has room for a full identifier so nothing is truncated to an
ellipsis; every level stays visible so the path you took is legible; and it is
trivially keyboard-navigable. A treemap would have been quicker to build and
would have made every label unreadable.

Time is **not** an axis here. It appears once, in the span band, for the current
selection — a time series of one thing is legible, forty at once is texture.

Reaching one decision must always be three clicks: pick a domain, pick a name,
and the evidence panel becomes that name's occurrences with the full chain
(`n`/`p` to step). If a change makes the chain harder to reach than that, it is
the wrong change.

Adding a view: view file + route (`main.ts`) + an entry in `Frame.vue`'s `PLACES`
+ a palette entry (`ui/Palette.vue`).

Build check: `npm run build` (runs `vue-tsc`). Dev: `npm run dev` with a backend
on 127.0.0.1:8089 — `python3 scripts/uidev.py` from the repo root gives one with
synthetic traffic (login `admin` / `admin`).

## 6. Conventions the older views still follow

`Pulse`, `QueryLog`, `Explore`, `Rules`, `Collateral`, `Clients`, `Privacy`,
`System`, `Audit` and `Settings` have not been rebuilt yet and still use
`app.css` (`.card`, `.tbl`, `.tiles`, the `ui/` chart primitives). They are
readable because `bailiwick.css` remaps the legacy tokens onto the new palette.
Two rules while they remain:

- **Do not extend the legacy system.** New shared classes go in
  `bailiwick.css`. Rebuilding one of those views means moving it onto §1–§2, not
  adding to `app.css`.
- What was good there is kept: every table exports (CSV/NDJSON via
  `lib/util.ts`), domains and client addresses are always clickable pivots
  (`store.inspect`), and errors surface through `store.toast`.
