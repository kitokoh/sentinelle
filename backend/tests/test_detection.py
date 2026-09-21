"""Detection engine tests (v0.3, issue #2).

Each of the three shipped rules is pinned twice: a fixture that must **fire**
and a fixture that must stay **silent**. `now` is injected everywhere so the
suite never depends on wall-clock time.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.services import detection
from app.services.detection import Rule

NOW = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)


def event(seconds_ago: float, **overrides) -> dict:
    """A normalized sensor event ``seconds_ago`` before NOW."""
    base = {
        "occurred_at": NOW - timedelta(seconds=seconds_ago),
        "event_type": "flow",
        "src_ip": "10.0.0.9",
        "src_port": 40000,
        "dst_ip": "10.0.0.10",
        "dst_port": 80,
        "proto": "TCP",
        "app_proto": "http",
    }
    base.update(overrides)
    return base


def kinds(detections) -> list[str]:
    return sorted(detection.kind for detection in detections)


# --------------------------------------------------------------------------- #
# Rule loading / validation
# --------------------------------------------------------------------------- #


def test_shipped_rule_file_loads_the_three_documented_rules():
    rules = detection.load_rules()
    by_name = {rule.name: rule for rule in rules}

    assert set(by_name) == {"port_scan", "ssh_bruteforce", "beaconing"}
    assert by_name["port_scan"].kind == "port_scan"
    assert by_name["port_scan"].threshold == 20
    assert by_name["port_scan"].window_seconds == 60
    assert by_name["ssh_bruteforce"].threshold == 10
    assert by_name["ssh_bruteforce"].window_seconds == 300
    assert by_name["beaconing"].min_samples == 5


def test_load_rules_falls_back_to_builtins_when_the_file_is_absent(tmp_path):
    rules = detection.load_rules(tmp_path / "absent.yaml")
    assert {rule.name for rule in rules} == {"port_scan", "ssh_bruteforce", "beaconing"}


def test_load_rules_reads_a_custom_file(tmp_path):
    custom = tmp_path / "rules.yaml"
    custom.write_text(
        "version: 1\nrules:\n"
        "  - name: tiny_scan\n    kind: port_scan\n    severity: critical\n"
        "    window_seconds: 10\n    threshold: 2\n",
        encoding="utf-8",
    )

    rules = detection.load_rules(custom)

    assert len(rules) == 1
    assert rules[0].name == "tiny_scan"
    assert rules[0].severity == "critical"
    assert rules[0].threshold == 2


def test_parse_rules_rejects_an_unknown_kind(tmp_path):
    """A silently ignored rule is a blind spot — this must fail loudly."""
    with pytest.raises(ValueError, match="unknown kind"):
        detection.parse_rules({"rules": [{"name": "x", "kind": "magic"}]})


def test_parse_rules_requires_a_name():
    with pytest.raises(ValueError, match="'name' is required"):
        detection.parse_rules({"rules": [{"kind": "port_scan"}]})


def test_parse_rules_requires_at_least_one_rule():
    with pytest.raises(ValueError, match="No detection rule"):
        detection.parse_rules({"rules": []})


# --------------------------------------------------------------------------- #
# port_scan
# --------------------------------------------------------------------------- #

PORT_SCAN_RULE = Rule(name="port_scan", kind="port_scan", severity="high", window_seconds=60, threshold=20)
SSH_RULE = Rule(name="ssh_bruteforce", kind="ssh_bruteforce", severity="high", window_seconds=300, threshold=10)
BEACON_RULE = Rule(name="beaconing", kind="beaconing", severity="medium", window_seconds=3600, threshold=5)


def test_port_scan_fires_above_the_threshold():
    scan = [event(seconds_ago=i, dst_port=1000 + i) for i in range(25)]

    detections = detection.evaluate(scan, rules=[PORT_SCAN_RULE], now=NOW)

    assert len(detections) == 1
    assert detections[0].kind == "port_scan"
    assert detections[0].severity == "high"
    assert detections[0].event_count == 25
    assert detections[0].dedup_key == "port_scan|10.0.0.9|-|-"
    # 25 distinct ports against a threshold of 20 -> 25/40 = 0.625.
    assert detections[0].confidence == pytest.approx(0.625)


def test_port_scan_stays_silent_at_the_threshold():
    """Exactly `threshold` ports is not a scan — the rule is strictly greater."""
    scan = [event(seconds_ago=i, dst_port=1000 + i) for i in range(20)]

    assert detection.evaluate(scan, rules=[PORT_SCAN_RULE], now=NOW) == []


def test_port_scan_stays_silent_when_activity_is_spread_outside_the_window():
    # 25 distinct ports, but one every 6 s -> only ~10 land inside the 60 s window.
    scan = [event(seconds_ago=i * 6, dst_port=1000 + i) for i in range(25)]

    assert detection.evaluate(scan, rules=[PORT_SCAN_RULE], now=NOW) == []


def test_port_scan_is_tracked_per_source():
    """Two half-scans from two hosts are not one scan."""
    events = [event(seconds_ago=i, dst_port=1000 + i, src_ip="10.0.0.9") for i in range(12)]
    events += [event(seconds_ago=i, dst_port=2000 + i, src_ip="10.0.0.11") for i in range(12)]

    assert detection.evaluate(events, rules=[PORT_SCAN_RULE], now=NOW) == []


def test_port_scan_ignores_events_without_a_destination_port():
    scan = [event(seconds_ago=i, dst_port=None) for i in range(30)]
    assert detection.evaluate(scan, rules=[PORT_SCAN_RULE], now=NOW) == []


# --------------------------------------------------------------------------- #
# ssh_bruteforce
# --------------------------------------------------------------------------- #


def ssh_event(seconds_ago: float, src_ip="10.0.0.9", dst_ip="10.0.0.20") -> dict:
    return event(
        seconds_ago,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=22,
        app_proto="ssh",
        event_type="alert",
    )


def test_ssh_bruteforce_fires_above_the_threshold():
    # Deliberately irregular spacing so the beaconing rule cannot also fire.
    offsets = [2, 9, 17, 26, 38, 47, 61, 88, 102, 137, 158, 181]
    attempts = [ssh_event(seconds_ago=offset) for offset in offsets]

    detections = detection.evaluate(attempts, rules=[SSH_RULE], now=NOW)

    assert len(detections) == 1
    assert detections[0].kind == "ssh_bruteforce"
    assert detections[0].event_count == 12
    assert detections[0].dst_ip == "10.0.0.20"
    assert detections[0].dst_port == 22
    assert detections[0].confidence == pytest.approx(12 / 20)


def test_ssh_bruteforce_stays_silent_at_the_threshold():
    attempts = [ssh_event(seconds_ago=offset) for offset in [1, 9, 17, 26, 38, 47, 61, 88, 102, 137]]
    assert detection.evaluate(attempts, rules=[SSH_RULE], now=NOW) == []


def test_ssh_bruteforce_stays_silent_outside_the_window():
    attempts = [ssh_event(seconds_ago=offset) for offset in range(0, 900, 60)]  # 15 attempts over 15 min
    assert detection.evaluate(attempts, rules=[SSH_RULE], now=NOW) == []


def test_ssh_bruteforce_recognises_ssh_by_app_proto_too():
    """Not every sensor fills dest_port — app_proto is the second signal."""
    attempts = [ssh_event(seconds_ago=offset, dst_ip="10.0.0.21") for offset in [1, 9, 17, 26, 38, 47, 61, 88, 102, 137, 158]]
    attempts = [dict(a, dst_port=2222, app_proto="ssh") for a in attempts]

    detections = detection.evaluate(attempts, rules=[SSH_RULE], now=NOW)

    assert len(detections) == 1
    assert detections[0].dst_ip == "10.0.0.21"


# --------------------------------------------------------------------------- #
# beaconing
# --------------------------------------------------------------------------- #


def beacon_event(index: int, step: int, jitter: int = 0, dst_port=8443) -> dict:
    return event(
        seconds_ago=(index * step) + jitter,
        dst_ip="192.0.2.50",
        dst_port=dst_port,
    )


def test_beaconing_fires_on_a_regular_interval():
    beats = [beacon_event(i, step=60) for i in range(6)]  # 0, 60, … 300 s ago

    detections = detection.evaluate(beats, rules=[BEACON_RULE], now=NOW)

    assert len(detections) == 1
    assert detections[0].kind == "beaconing"
    assert detections[0].event_count == 6
    assert detections[0].dst_port == 8443
    # Perfectly regular -> full confidence.
    assert detections[0].confidence == 1.0
    assert detections[0].metadata["mean_interval_seconds"] == pytest.approx(60.0)


def test_beaconing_tolerates_a_little_jitter():
    beats = [beacon_event(i, step=60, jitter=jitter) for i, jitter in enumerate([0, 3, -2, 1, -1, 2])]

    detections = detection.evaluate(beats, rules=[BEACON_RULE], now=NOW)

    assert len(detections) == 1
    assert detections[0].confidence < 1.0
    assert detections[0].confidence > 0.9


def test_beaconing_stays_silent_on_irregular_traffic():
    beats = [beacon_event(i, step=step) for i, step in enumerate([5, 400, 20, 900, 60, 7])]

    assert detection.evaluate(beats, rules=[BEACON_RULE], now=NOW) == []


def test_beaconing_stays_silent_below_the_sample_floor():
    beats = [beacon_event(i, step=60) for i in range(4)]  # min_samples = 5

    assert detection.evaluate(beats, rules=[BEACON_RULE], now=NOW) == []


def test_beaconing_is_tracked_per_destination_port():
    """Six regular beats split across two ports is not a beacon on either."""
    beats = [beacon_event(i, step=60, dst_port=8443 if i % 2 else 8444) for i in range(6)]

    assert detection.evaluate(beats, rules=[BEACON_RULE], now=NOW) == []


# --------------------------------------------------------------------------- #
# Engine contract
# --------------------------------------------------------------------------- #


def test_evaluate_returns_a_detection_per_fired_rule():
    events = [event(seconds_ago=i, dst_port=1000 + i) for i in range(25)]
    events += [ssh_event(seconds_ago=offset) for offset in [2, 9, 17, 26, 38, 47, 61, 88, 102, 137, 158, 181]]

    found = kinds(detection.evaluate(events, rules=[PORT_SCAN_RULE, SSH_RULE], now=NOW))

    assert found == ["port_scan", "ssh_bruteforce"]


def test_evaluate_ignores_events_outside_any_window():
    assert detection.evaluate([event(seconds_ago=99_999, dst_port=1)], rules=[PORT_SCAN_RULE], now=NOW) == []


def test_evaluate_ignores_datetime_less_events():
    assert detection.evaluate([{"src_ip": "10.0.0.9", "dst_port": 1}], rules=[PORT_SCAN_RULE], now=NOW) == []


def test_evaluate_accepts_orm_style_objects():
    class FakeEvent:
        occurred_at = NOW - timedelta(seconds=5)
        src_ip = "10.0.0.9"
        dst_port = 1234
        dst_ip = "10.0.0.10"
        app_proto = "http"
        event_type = "flow"
        proto = "TCP"

    # A zero threshold makes the rule fire on a single event, keeping the test
    # focused on attribute access rather than on the counting logic.
    rule = Rule(name="tiny", kind="port_scan", severity="low", window_seconds=60, threshold=0)

    detections = detection.evaluate([FakeEvent()], rules=[rule], now=NOW)

    assert len(detections) == 1
    assert detections[0].confidence == 1.0


def test_evaluate_raises_on_an_unknown_kind_reaching_the_engine():
    with pytest.raises(ValueError, match="Unknown rule kind"):
        detection.evaluate([], rules=[Rule(name="x", kind="nope")], now=NOW)


def test_naive_now_is_treated_as_utc():
    naive_now = datetime(2026, 9, 21, 12, 0, 0)
    scan = [event(seconds_ago=i, dst_port=1000 + i) for i in range(25)]

    assert len(detection.evaluate(scan, rules=[PORT_SCAN_RULE], now=naive_now)) == 1
