# DNSGuard Console frontend

**Read DESIGN.md before writing any code here.** It is a binding contract for
the "Bailiwick" design language: **two** type faces (mono for identifiers, the
system UI face for everything else — there is no serif and no prose voice),
**common words** for outcomes (blocked, cached, forwarded — never "withheld" or
"no round trip"), conventional outcome colours (blocked red, failed amber,
cached green, forwarded blue), one plane with hairlines instead of cards, drawn
icons only, charts chosen for their geometry with donuts/gauges/treemaps/KPI
tiles banned, tokens-only colours and the `--b-1..--b-6` space scale, no new
dependencies, no scoped CSS in views, and every view a permalink.

**No explanatory prose in the interface.** No view carries an essay under its
title, no column header explains what clicking does, and a missing control is
never replaced by a paragraph about why it is missing. If a setting is worth
documenting it goes in the docs; if it is worth having it goes in Settings,
which is generated from `dnsguard/api/settings.py`.

Quick facts:
- Vue 3 + vue-router only. Hand-drawn SVG charts in `src/ui/` — no libraries.
- All styling lives in `src/styles/bailiwick.css`. `tokens.css`/`app.css` are
  legacy, kept only for the not-yet-rebuilt views — do not extend them.
- `src/views/Browse.vue` is the primary surface and the reference for new work.
- Logic with judgement in it lives in `src/lib/` behind a test that Node runs
  directly: `node src/lib/facets.test.ts`, `node src/lib/qlang.test.ts`.
- Live data comes from the WebSocket store (`src/lib/store.ts`) — never open
  a second socket; REST via `src/lib/api.ts`.
- New view = view file + route (main.ts) + an entry in Frame.vue PLACES +
  palette entry (ui/Palette.vue). Shell.vue is gone; Frame.vue is the chrome.
- Build check: `npm run build` (includes vue-tsc). Dev: `npm run dev` with a
  dnsguard backend on 127.0.0.1:8089 (`python3 -m dnsguard --config …`).
- Backend API surface: `dnsguard/api/server.py` (REST + `/api/v1/ws`).
- The previous frontend implementation is archived at
  `backup/web-ui-2026-07-07/` (repo root) — reference only, do not resurrect.
