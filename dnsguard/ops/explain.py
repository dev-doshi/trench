"""One question, answered by every subsystem that knows part of it.

"Why is this broken?" is the only question a household ever asks a DNS server,
and answering it today means reading the query log, then the rules, then the
cache, then the device list, and joining them by hand. Everything needed is
already in the process; nothing composed it.

This does. Given a name — and optionally the device that complained — it
reports, in the order the pipeline itself would have consulted them:

  * is it ours (a local zone, or a name published from a DHCP lease)?
  * would a policy stage block it, and which one: blocked service, safe
    browsing, a filter rule (with the rule text, the list, and whether an
    allow rule beat it), a listed answer address?
  * what is in the cache for it right now, stale or fresh?
  * what has actually happened to this name recently, per the query log?
  * is the device that asked even talking to this resolver any more?
  * and, if asked to, what happens when we resolve it right now — rcode,
    answers, and the RFC 8914 reason if one comes back.

The verdict line is written to be the answer, with the evidence under it.
"""
from __future__ import annotations

import time
from typing import Any

from ..filter import Action
from ..filter.ipmatch import answer_addresses
from ..log import get
from ..wire import Class, Message, Question, Type
from ..wire.name import Name
from ..wire.rrtypes import EDNSOption, Rcode, type_to_text

log = get("explain")


def _decision_dict(d) -> dict:
    return {"action": getattr(d.action, "name", str(d.action)).lower(),
            "rule": d.rule, "source": d.source, "reason": d.reason}


def _edns_errors(msg: Message) -> list[dict]:
    """RFC 8914 extended errors attached to a response."""
    out: list[dict] = []
    edns = getattr(msg, "edns", None)
    if edns is None:
        return out
    raw = (edns.get_option(EDNSOption.EXTENDED_ERROR)
           if hasattr(edns, "get_option") else None)
    if not raw or len(raw) < 2:
        return out
    code = int.from_bytes(raw[:2], "big")
    text = raw[2:].decode("utf-8", "replace")
    out.append({"code": code, "text": text})
    return out


async def explain(app, name: str, qtype: str = "A", client: str = "",
                  resolve: bool = False) -> dict:
    """The composed answer. Never raises: a subsystem that is switched off or
    unavailable contributes nothing rather than failing the whole report."""
    qname = name.strip().rstrip(".").lower()
    try:
        rtype = Type[qtype.upper()]
    except KeyError:
        rtype = Type.A
    report: dict[str, Any] = {
        "name": qname, "type": type_to_text(rtype), "client": client,
        "checked_at": int(time.time()), "findings": [],
    }
    findings: list[dict] = report["findings"]

    policy = None
    if client and app.clients is not None:
        policy = app.clients.identify(client)
        report["policy"] = {"name": getattr(policy, "name", ""),
                            "block": getattr(policy, "block", True),
                            "services": sorted(getattr(policy, "services", ()) or ()),
                            "upstream_group": getattr(policy, "upstream_group", "")}

    # --- is it ours? --------------------------------------------------------
    hostnames = getattr(app, "hostnames", None)
    if hostnames is not None:
        ip = hostnames.ip_for(qname)
        if ip:
            findings.append({"stage": "local", "verdict": "answered here",
                             "detail": f"a DHCP lease publishes {qname} as {ip}"})
    zones = getattr(app, "zones", None)
    if zones is not None and not getattr(zones, "empty", True):
        try:
            if zones.authoritative_for(Name.from_text(qname + ".")) is not None:
                findings.append({"stage": "zone", "verdict": "answered here",
                                 "detail": "this server is authoritative for it"})
        except Exception:
            pass

    # --- global switches ----------------------------------------------------
    pipe = app.pipeline
    if not pipe.enabled:
        findings.append({"stage": "switch", "verdict": "filtering off",
                         "detail": "blocking is switched off entirely"})
    elif pipe.paused(client):
        findings.append({"stage": "switch", "verdict": "paused",
                         "detail": "filtering is paused for this client"})

    # --- policy stages, in pipeline order -----------------------------------
    services = getattr(app, "services", None)
    if services is not None:
        sid = services.service_for(qname)
        if sid:
            selected = sid in set(getattr(policy, "services", ()) or ())
            findings.append({
                "stage": "service",
                "verdict": "blocked" if selected else "would block if selected",
                "detail": f"{qname} belongs to the '{sid}' service"
                          + ("" if selected else "; this client does not block it")})

    safebrowse = getattr(app, "safebrowse", None)
    if safebrowse is not None and policy is not None:
        cat = safebrowse.check(qname, safe_browse=getattr(policy, "safe_browse", False),
                               parental=getattr(policy, "parental", False))
        if cat:
            findings.append({"stage": "protection", "verdict": "blocked",
                             "detail": f"{cat} protection covers this name"})

    engine = app.filter
    if engine is not None:
        ctags = frozenset(getattr(policy, "ctags", ()) or ())
        names = frozenset(n for n in (getattr(policy, "name", "") or "",) if n)
        d = engine.match(qname, rtype, ctags=ctags, client=client, client_names=names)
        report["rule"] = _decision_dict(d)
        if d.action == Action.BLOCK:
            findings.append({"stage": "filter", "verdict": "blocked",
                             "detail": f"rule {d.rule or qname!r} from "
                                       f"{d.source or 'an unnamed list'}"})
        elif d.action == Action.ALLOW:
            findings.append({"stage": "filter", "verdict": "explicitly allowed",
                             "detail": f"allow rule {d.rule or qname!r} from "
                                       f"{d.source or 'an unnamed list'}"})
        elif d.action == Action.REWRITE:
            findings.append({"stage": "filter", "verdict": "rewritten",
                             "detail": d.reason or "a $dnsrewrite rule applies"})

    # --- the operator's own contract ----------------------------------------
    broken = [f for f in getattr(app, "contract_failures", [])
              if getattr(f.assertion, "name", "").strip("*.") in qname]
    for f in broken:
        findings.append({"stage": "contract", "verdict": "assertion failing",
                         "detail": f.describe()})

    # --- cache --------------------------------------------------------------
    cache = getattr(app, "cache", None)
    if cache is not None:
        probe = Message(id=0)
        probe.questions.append(Question(Name.from_text(qname + "."), rtype, Class.IN))
        key = cache.key_for(probe)
        if key is not None:
            hit = cache.get(key, allow_stale=True)
            if hit is not None:
                resp, stale = hit
                report["cache"] = {"present": True, "stale": bool(stale),
                                   "rcode": Rcode(resp.rcode).name
                                   if resp.rcode in [r.value for r in Rcode] else resp.rcode,
                                   "answers": answer_addresses(resp)}
            else:
                report["cache"] = {"present": False}

    # --- what has actually been happening -----------------------------------
    querylog = getattr(app, "querylog", None)
    if querylog is not None:
        try:
            rows = await querylog.search(qname=qname, limit=5)
            report["recent"] = [
                {"ts": r.get("ts"), "client": r.get("client_ip"),
                 "action": r.get("action"), "rcode": r.get("rcode"),
                 "reason": r.get("reason")} for r in rows]
            hist = await querylog.history(qname, limit=5)
            report["history"] = hist
            if len(hist) > 1:
                findings.append({
                    "stage": "history", "verdict": "answer changed",
                    "detail": f"this name has resolved to {len(hist)} different "
                              f"answer sets in the log; most recently "
                              f"{', '.join(hist[0]['answers']) or 'no addresses'}"})
        except Exception:
            log.exception("query log lookup failed while explaining %s", qname)

    # --- is the device even here? -------------------------------------------
    ledger = getattr(app, "ledger", None)
    if ledger is not None and client:
        row = ledger.device(client)
        if row is not None:
            report["device"] = row
            if row["status"] in ("bypassing", "silent"):
                findings.append({
                    "stage": "device", "verdict": row["status"],
                    "detail": f"{client} is not asking this resolver: {row['evidence']}"})

    # --- resolve it now, if asked -------------------------------------------
    if resolve:
        query = Message(id=0)
        query.set_flag(0x0100, True)     # RD
        query.questions.append(Question(Name.from_text(qname + "."), rtype, Class.IN))
        try:
            ctx = await pipe.resolve_ctx(query, client or "127.0.0.1", proto="internal")
            resp = ctx.response
            report["live"] = {
                "action": ctx.action,
                "reason": ctx.reason,
                "upstream": ctx.upstream,
                "rcode": Rcode(resp.rcode).name if resp is not None
                and resp.rcode in [r.value for r in Rcode] else getattr(resp, "rcode", None),
                "answers": answer_addresses(resp) if resp is not None else [],
                "extended_errors": _edns_errors(resp) if resp is not None else [],
            }
            if resp is not None and resp.rcode == Rcode.SERVFAIL:
                findings.append({
                    "stage": "resolution", "verdict": "SERVFAIL",
                    "detail": ctx.reason or "resolution failed upstream "
                                            "(DNSSEC validation or an unreachable server)"})
        except Exception as e:
            report["live"] = {"error": str(e)}

    report["verdict"] = _verdict(report, findings)
    return report


def _verdict(report: dict, findings: list[dict]) -> str:
    """One sentence. The evidence is already in the report; this says which of
    it is the answer."""
    order = ["switch", "device", "contract", "filter", "service", "protection",
             "resolution", "zone", "local"]
    for stage in order:
        for f in findings:
            if f["stage"] != stage:
                continue
            if f["verdict"] in ("blocked", "paused", "filtering off", "bypassing",
                                "silent", "SERVFAIL", "assertion failing",
                                "answered here", "rewritten", "explicitly allowed"):
                return f"{report['name']}: {f['verdict']} — {f['detail']}"
    live = report.get("live") or {}
    if live.get("action") in ("forwarded", "cached"):
        answers = ", ".join(live.get("answers", [])) or live.get("rcode", "no answer")
        return f"{report['name']}: resolves normally ({answers})"
    return (f"{report['name']}: nothing here blocks it — no rule, service or "
            f"protection matches")
