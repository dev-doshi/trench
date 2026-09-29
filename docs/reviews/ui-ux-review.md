# Trench UI/UX and developer-experience review

**Date:** 2026-09-29

## Scope

| Area | Code |
| --- | --- |
| Web console (Bailiwick) | `trench/web/frontend/src` (views, `ui/`, `lib/`, `styles/bailiwick.css`) |
| Built console | `trench/web/dist` (committed, rebuilt with `npm run build`) |
| CLI | `trench/cli/main.py` (`status`, `toggle`, `flush-cache`, `update`, `pause`, `why`, `query`, `regex-test`, `upgrade`) |
| Server support for search | `trench/store/querylog.py` (pushdown of the outcome filter) |

## Method

- Read every view and shared component. Then ran a real daemon, signed in, and
  used the console under Playwright at 1440, 1360, 1300, 1200, 1180, 1100, 1000,
  950, 900, 600, 390 and 320 px. Checked the browser console for errors,
  keyboard-only use, and both colour schemes.
- For the CLI, pointed each API command at nothing, at a non-Trench server, and
  at the daemon with no token, a rejected token and an under-scoped token, both
  at a terminal and piped.
- Every fix comes with a test where there is somewhere to put one:
  `src/lib/*.test.ts`, `tests/test_cli_*.py`, `tests/test_store.py`.

Findings are listed as **problem → what was done**. The residual issues are
left open deliberately.

## Bailiwick Web Console UX

- **Most of the nav was missing below 900 px.** The strip was hidden there, and
  the "Places" button that should replace it had no rule to show it. Phones had
  no way to move between screens except the `g` key. The button now shows, and
  the switch happens at 980 px. Between 900 and 980 px the strip used to clip
  silently, so the switch point moved up.
- **The header clipped at laptop widths.** Nav links were underlined, and the
  wordmark, button labels and shortcut hints all competed for one row. Links
  are no longer underlined, and the controls no longer wrap. Secondary text now
  drops in stages: the wordmark subtitle and shortcut hints below 1360 px, the
  button labels below 1180 px. At every width tested from 1000 to 1440 px, the
  nav, the frame and the page each overflow by 0 px.
- **Navigation was not a link.** The places were buttons that pushed routes, so
  middle-click, "open in new tab" and the browser status bar did not work. They
  are now `RouterLink`s with `aria-current="page"`.
- **An expired session left the console silently broken.** The WebSocket
  retried forever and the API calls failed one by one. Now a 401 from any call,
  or from the socket's expiry probe, returns you to sign-in with a reason.
  Sign-in errors say what was wrong rather than repeating the status code.
- **Toasts piled up and could not be dismissed.** They are now capped, each can
  be dismissed, and they are announced through a live region.
- **Unused preferences.** Settings kept local preferences that no screen read.
  They were removed, and every `localStorage` access now goes through a wrapper
  that survives private windows and blocked storage.
- **Exported CSV could run formulas.** A domain beginning with `=`, `+`, `-` or
  `@` was written as-is. Such cells are now neutralised. Downloads also release
  their object URLs.
- **Pivots were built by string concatenation.** "Show me this domain",
  "this client" and "this outcome" pasted raw values into a query. A value
  containing a quote or a space either broke the query or matched something
  else. Every pivot (Browse, Breakage, Evidence, Inspector) now goes through
  `term(field, value)`, which quotes the value correctly. Pivot targets that
  were `<span @click>` are now links or buttons.

## CLI Ergonomics & Diagnostic Clarity

- **Every failure looked the same.** "Is the daemon running?" was printed for a
  refused connection, a missing token, a revoked token, a token without the
  right scope, a 404 from the wrong service, a host that did not resolve, and a
  URL with no scheme. `_describe_failure` now tells these apart:
  - It names the scope the command needs (for example, *needs editor*).
  - It repeats the daemon's own refusal in the daemon's words.
  - It keeps the old hint only where the hint is true.
- **Tokens could only be passed on the command line.** Passing a token there
  leaves it in shell history and in `ps`. All API commands now read
  `TRENCH_URL` and `TRENCH_TOKEN`, and a trailing slash on the URL no longer
  breaks the request.
- **Output at a terminal was raw JSON.** `status`, `toggle`, `flush-cache`,
  `update` and `pause` now answer in a sentence at a terminal. For example:
  *filtering paused for everyone until 14:05:10; `trench pause 0` resumes now*.
  When piped, or with `--json`, they print the unchanged JSON, so existing
  scripts keep working.
- **Usage mistakes exit 2, and the message shows valid input.** This covers:
  - `pause soon`: suggests `30s`, `5m`, `1h` or `0`; durations over 24 h are refused
  - an unknown record type: suggests `A`, `AAAA`, `MX`, `TXT`, `HTTPS`…
  - an unknown transport: lists `@udp`, `@tcp`, `@tls`, `@https`, `@quic`
- **Failures to reach or persuade the daemon exit 1.**
- **`why`:**
  - Its plural read "1 recent queries". It now reads "1 recent query".
  - It crashed on a finding with missing fields.
  - With `--resolve`, it hid the reason a live resolution failed.
  - It used the default timeout even though a cold `--resolve` can take several
    seconds. It now allows 20 s.
- **`query`** reports the elapsed time and the server asked, as `dig` does.
  Failures name the server and transport used.
- **`regex-test`:**
  - An unreadable `@file` is reported as a plain error instead of a traceback.
  - A rule that does not parse says which syntaxes are accepted.
- `docs/cli.md` documents the environment variables, the terminal/JSON split,
  the error causes, the exit codes, and the scope each command needs.

## Search & Live Log Usability

- **Each keystroke in the search box discarded the previous result.** While a
  query was half-typed, Browse and Log dropped to an empty table. Both now keep
  filtering with the last query that parsed. The error line says so: *— still
  showing the last query that made sense*.
- **Server-side filtering fell out of date.** Changing the part of the query
  sent to the server (time, action/outcome) did not reload, so the page filtered
  a server result that no longer matched. Browse and Log now reload 350 ms
  after that part changes. A sequence guard drops replies to superseded
  requests.
- **A list of outcomes filtered in the browser.** Previously only one outcome
  could go to the server. An outcome list such as `blocked | refused` now goes
  to the server as an `IN (…)`, so the page holds matching rows rather than a
  sample of all rows (`querylog.py`, with a test).
- **Browse's "now" did not move.** The end of the time window was fixed when
  the page loaded, so live rows arriving later fell outside the window and were
  dropped. The end of the window now moves forward on every load and every
  live flush.
- **The Live tape did not stop while you read it.** The tape was said to freeze
  on hover, but rows kept shifting under the pointer. Hover or keyboard focus
  now shows a snapshot until you move away.
- **Rows beyond the in-memory cap disappeared silently.** Past 600 rows the
  oldest were discarded with no sign. The cap is now explicit, and a notice
  appears when rows have been dropped.
- **Several WebSocket connections could run at once.** Reconnects could stack
  sockets and duplicate live rows. There is now one socket, with jittered
  backoff. It reconnects straight away when the tab becomes visible or the
  network returns.
- **Keyboard:**
  - Browse's shortcuts no longer fire in select menus or editable content,
    under modifier keys, or while the inspector, palette or place sheet is open.
  - Enter and Space on a focused button now act on that button rather than on
    the row cursor.
  - The cursor row scrolls into view.
- **Shared URLs:** URL parameters are checked against the known facets, so a
  hand-edited or outdated URL cannot break the page.

## Accessibility & Performance Polish

- **Contrast.** The two faintest ink tokens were below 4.5:1 in both schemes
  and were raised:
  - dark: `--b-ink-3` `#a0a8b5`, `--b-ink-4` `#848c9b`
  - light: `--b-ink-3` `#4f5663`, `--b-ink-4` `#646b79`
- **Landmarks and focus.**
  - A skip link, previously always visible and now shown only on focus, jumps
    to `<main id="main">`.
  - The place sheet, the inspector and the palette move focus in when opened
    and return it to what opened them. Esc closes each.
  - Focusable rows show `:focus-visible` outlines.
- **Roles and state.**
  - The palette is a combobox with `aria-activedescendant`.
  - Browse rows are a listbox with `aria-selected`.
  - The Live tape is a list of focusable items that open on Enter.
  - Menus expose `aria-haspopup`/`aria-expanded`.
  - The time window is a group of `aria-pressed` toggles.
  - The search input is labelled and marked `aria-invalid`, and its error text
    is linked with `aria-describedby`.
  - Connection state is a `role="status"`.
- **Stale results.** The inspector ignores replies for rows you have already
  moved past, so a slow reply can no longer overwrite the one you are reading.
- **Build.** No dependencies were added. The console is still Vue 3 and
  vue-router, and `trench/web/dist` has been rebuilt from this source.

## Residual

- **Browse at 320 px.** The time-window buttons scroll sideways inside their
  own strip (the page itself no longer overflows once the chart legend wraps).
- **The Live tape has no virtualisation.** It relies on the 600-row cap; above
  that the cap drops rows (with the notice) rather than slowing the page.
- **No automated browser test.** The console is not run in a browser in CI;
  the Playwright checks above were run by hand. The logic-bearing modules have
  unit tests (`node src/lib/qlang.test.ts`, `node src/lib/facets.test.ts`).
