"""Prometheus text exposition (no client library; we emit the format directly)."""
from __future__ import annotations

from ..stats import Counters
from ..stats.counters import LATENCY_BOUNDS_US
from ..version import __version__


def _line(name: str, value, labels: str = "") -> str:
    return f"{name}{{{labels}}} {value}" if labels else f"{name} {value}"


def _lv(value: str) -> str:
    """A label value, escaped per the exposition format.

    Upstream labels carry user-supplied text (`tls://9.9.9.9#dns.quad9.net`),
    and one unescaped backslash or quote in there produces a scrape the whole
    of Prometheus rejects — not just the offending line.
    """
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def render(counters: Counters, cache, filter_size: int, fast=None,
           pipeline=None) -> str:
    snap = counters.snapshot(top=0)
    out: list[str] = []

    out.append("# HELP dnsguard_build_info Build information")
    out.append("# TYPE dnsguard_build_info gauge")
    out.append(_line("dnsguard_build_info", 1, f'version="{__version__}"'))

    out.append("# HELP dnsguard_queries_total Total DNS queries handled")
    out.append("# TYPE dnsguard_queries_total counter")
    out.append(_line("dnsguard_queries_total", snap["total"]))

    out.append("# HELP dnsguard_query_actions_total Queries by action")
    out.append("# TYPE dnsguard_query_actions_total counter")
    for action, n in counters.by_action.items():
        out.append(_line("dnsguard_query_actions_total", n, f'action="{action}"'))

    out.append("# HELP dnsguard_query_types_total Queries by record type")
    out.append("# TYPE dnsguard_query_types_total counter")
    for qtype, n in counters.by_qtype.items():
        out.append(_line("dnsguard_query_types_total", n, f'type="{qtype}"'))

    out.append("# HELP dnsguard_blocked_total Blocked queries")
    out.append("# TYPE dnsguard_blocked_total counter")
    out.append(_line("dnsguard_blocked_total", snap["blocked"]))

    out.append("# HELP dnsguard_block_ratio Fraction of queries blocked")
    out.append("# TYPE dnsguard_block_ratio gauge")
    out.append(_line("dnsguard_block_ratio", round(snap["block_pct"] / 100, 4)))

    out.append("# HELP dnsguard_cache_size Entries currently cached")
    out.append("# TYPE dnsguard_cache_size gauge")
    out.append(_line("dnsguard_cache_size", cache.size))
    for k, v in cache.stats.items():
        out.append(_line("dnsguard_cache_events_total", v, f'event="{k}"'))

    out.append("# HELP dnsguard_blocklist_size Domains/rules in the filter index")
    out.append("# TYPE dnsguard_blocklist_size gauge")
    out.append(_line("dnsguard_blocklist_size", filter_size))

    out.append("# HELP dnsguard_query_rcodes_total Answers by response code")
    out.append("# TYPE dnsguard_query_rcodes_total counter")
    for rcode, n in counters.by_rcode.items():
        out.append(_line("dnsguard_query_rcodes_total", n, f'rcode="{_lv(rcode)}"'))

    out.append("# HELP dnsguard_upstream_answers_total Answers by upstream server")
    out.append("# TYPE dnsguard_upstream_answers_total counter")
    for server, n in counters.upstreams.most_common(64):
        out.append(_line("dnsguard_upstream_answers_total", n, f'upstream="{_lv(server)}"'))

    out.append("# HELP dnsguard_clients_seen Distinct clients seen since start")
    out.append("# TYPE dnsguard_clients_seen gauge")
    out.append(_line("dnsguard_clients_seen", len(counters.clients)))

    out.append("# HELP dnsguard_detections_total Behavioural detections by kind")
    out.append("# TYPE dnsguard_detections_total counter")
    out.append(_line("dnsguard_detections_total", sum(counters.dga.values()), 'kind="dga"'))
    out.append(_line("dnsguard_detections_total", sum(counters.tunnel.values()),
                     'kind="tunnel"'))

    # A histogram, not a mean. An average latency cannot show a p99 regression,
    # which is the only latency question anyone actually asks of a resolver.
    out.append("# HELP dnsguard_query_duration_seconds Resolve latency")
    out.append("# TYPE dnsguard_query_duration_seconds histogram")
    cum = 0
    for i, bound in enumerate(LATENCY_BOUNDS_US):
        cum += counters.latency_hist[i]
        out.append(_line("dnsguard_query_duration_seconds_bucket", cum,
                         f'le="{bound / 1e6:g}"'))
    cum += counters.latency_hist[-1]
    out.append(_line("dnsguard_query_duration_seconds_bucket", cum, 'le="+Inf"'))
    out.append(_line("dnsguard_query_duration_seconds_sum",
                     round(counters.latency_us_sum / 1e6, 6)))
    out.append(_line("dnsguard_query_duration_seconds_count", cum))

    out.append("# HELP dnsguard_avg_latency_ms Average resolve latency (ms)")
    out.append("# TYPE dnsguard_avg_latency_ms gauge")
    out.append(_line("dnsguard_avg_latency_ms", snap["avg_latency_ms"]))

    if fast is not None:
        # The replay ratio is the one number that says whether the fast path is
        # doing anything. A low one is not a fault — it means traffic is diverse,
        # or a feature that makes replies client-specific is switched on — but it
        # is the difference between "enabled" and "in use".
        out.append("# HELP dnsguard_fastpath_total Wire-resident replay outcomes")
        out.append("# TYPE dnsguard_fastpath_total counter")
        out.append(_line("dnsguard_fastpath_total", fast.hits, 'event="hit"'))
        out.append(_line("dnsguard_fastpath_total", fast.stores, 'event="recorded"'))
        out.append("# HELP dnsguard_fastpath_entries Recorded replies held")
        out.append("# TYPE dnsguard_fastpath_entries gauge")
        out.append(_line("dnsguard_fastpath_entries", fast.size))
        out.append("# HELP dnsguard_fastpath_usable Replay currently permitted")
        out.append("# TYPE dnsguard_fastpath_usable gauge")
        out.append(_line("dnsguard_fastpath_usable", int(fast.usable)))

    if pipeline is not None:
        out.append("# HELP dnsguard_filtering_enabled Global filtering switch")
        out.append("# TYPE dnsguard_filtering_enabled gauge")
        out.append(_line("dnsguard_filtering_enabled", int(bool(pipeline.enabled))))
        out.append("# HELP dnsguard_filtering_paused Filtering suspended by a timed pause")
        out.append("# TYPE dnsguard_filtering_paused gauge")
        out.append(_line("dnsguard_filtering_paused", int(bool(pipeline.paused_any))))

    out.append("# HELP dnsguard_uptime_seconds Process uptime")
    out.append("# TYPE dnsguard_uptime_seconds gauge")
    out.append(_line("dnsguard_uptime_seconds", snap["uptime"]))
    return "\n".join(out) + "\n"
