"""Prometheus exposition: labelled series, the latency histogram, escaping."""
from __future__ import annotations

import json
from pathlib import Path

from dnsguard.cache import Cache
from dnsguard.ops import metrics
from dnsguard.stats import Counters
from dnsguard.stats.counters import LATENCY_BOUNDS_US


def render(counters: Counters, **kw) -> str:
    return metrics.render(counters, Cache(), 10, **kw)


def series(text: str, name: str) -> list[str]:
    return [ln for ln in text.splitlines()
            if ln.startswith(name + "{") or ln.startswith(name + " ")]


def test_rcode_and_upstream_labels_are_exported():
    c = Counters()
    c.record(client="10.0.0.1", qname="a.test", qtype="A", action="forwarded",
             rcode="NOERROR", upstream="1.1.1.1:53", elapsed_us=900)
    c.record(client="10.0.0.2", qname="b.test", qtype="AAAA", action="failed",
             rcode="SERVFAIL", upstream="9.9.9.9:53", elapsed_us=3000)
    text = render(c)
    assert 'dnsguard_query_rcodes_total{rcode="SERVFAIL"} 1' in text
    assert 'dnsguard_upstream_answers_total{upstream="1.1.1.1:53"} 1' in text
    assert "dnsguard_clients_seen 2" in text


def test_latency_histogram_is_cumulative_and_totals_agree():
    c = Counters()
    for us in (50, 900, 900, 400_000):
        c.record(client="10.0.0.1", qname="a.test", qtype="A", action="forwarded",
                 elapsed_us=us)
    text = render(c)
    buckets = {}
    for line in series(text, "dnsguard_query_duration_seconds_bucket"):
        le = line.split('le="')[1].split('"')[0]
        buckets[le] = int(line.rsplit(" ", 1)[1])
    ordered = [buckets[f"{b / 1e6:g}"] for b in LATENCY_BOUNDS_US] + [buckets["+Inf"]]
    assert ordered == sorted(ordered)                 # cumulative, never decreasing
    assert buckets["+Inf"] == 4                       # every sample counted
    assert "dnsguard_query_duration_seconds_count 4" in text
    assert buckets["0.0001"] == 1                     # the 50 us sample only


def test_label_values_are_escaped():
    """An upstream label carries operator text; one raw quote breaks the scrape
    for every metric in the response, not just this line."""
    c = Counters()
    c.record(client="10.0.0.1", qname="a.test", qtype="A", action="forwarded",
             upstream='tls://9.9.9.9#dns."quad9".net\\x', elapsed_us=10)
    line = series(render(c), "dnsguard_upstream_answers_total")[0]
    body = line.split("{", 1)[1].rsplit("}", 1)[0]
    assert body.count('"') == 2 + 2                   # the two delimiters + two escaped
    assert '\\"quad9\\"' in body


def test_pause_state_is_exported(monkeypatch):
    class FakePipeline:
        enabled = True
        paused_any = True

    text = render(Counters(), pipeline=FakePipeline())
    assert "dnsguard_filtering_enabled 1" in text
    assert "dnsguard_filtering_paused 1" in text


def test_shipped_grafana_dashboard_is_valid_json_and_matches_metric_names():
    path = Path(__file__).resolve().parent.parent / "deploy" / "grafana-dashboard.json"
    board = json.loads(path.read_text())
    assert board["title"] == "DNSGuard"
    exprs = " ".join(t["expr"] for p in board["panels"] for t in p.get("targets", []))
    exported = render(Counters(), pipeline=None)
    for metric in ("dnsguard_queries_total", "dnsguard_query_actions_total",
                   "dnsguard_query_duration_seconds_bucket", "dnsguard_cache_size",
                   "dnsguard_query_rcodes_total", "dnsguard_upstream_answers_total",
                   "dnsguard_detections_total", "dnsguard_clients_seen"):
        assert metric in exprs, f"dashboard does not use {metric}"
        # every metric the dashboard charts must actually be exported
        assert metric.replace("_bucket", "") in exported
