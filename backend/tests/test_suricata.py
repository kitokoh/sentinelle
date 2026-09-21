"""Suricata EVE parsing & tailing tests (v0.3, issue #1).

Pure functions only — no database, no sensor: fixtures are raw EVE lines, which
is exactly what the acceptance criterion asks for ("fixture EVE → alertes
insérées et filtrables" is covered in test_ingest.py).
"""

import json
from datetime import datetime, timedelta, timezone

from app.services import suricata


def eve_alert(**overrides) -> dict:
    record = {
        "timestamp": "2026-09-21T03:14:15.123456+0000",
        "flow_id": 1234567890,
        "event_type": "alert",
        "src_ip": "10.20.30.40",
        "src_port": 44321,
        "dest_ip": "10.20.30.10",
        "dest_port": 22,
        "proto": "TCP",
        "app_proto": "ssh",
        "alert": {"signature": "ET SCAN Potential SSH Scan", "severity": 1},
    }
    record.update(overrides)
    return record


# --------------------------------------------------------------------------- #
# Timestamps & severity
# --------------------------------------------------------------------------- #


def test_parse_timestamp_accepts_suricata_offset_without_colon():
    """Suricata writes +0000; fromisoformat needs +00:00 on Python 3.10."""
    parsed = suricata.parse_timestamp("2026-09-21T03:14:15.123456+0000")
    assert parsed == datetime(2026, 9, 21, 3, 14, 15, 123456, tzinfo=timezone.utc)


def test_parse_timestamp_accepts_naive_and_zulu_forms():
    assert suricata.parse_timestamp("2026-09-21T03:14:15") == datetime(
        2026, 9, 21, 3, 14, 15, tzinfo=timezone.utc
    )
    assert suricata.parse_timestamp("2026-09-21T03:14:15Z") == datetime(
        2026, 9, 21, 3, 14, 15, tzinfo=timezone.utc
    )


def test_parse_timestamp_returns_none_on_garbage():
    assert suricata.parse_timestamp("not-a-date") is None
    assert suricata.parse_timestamp(None) is None
    assert suricata.parse_timestamp("") is None


def test_severity_from_signature_level_maps_the_three_suricata_levels():
    assert suricata.severity_from_signature_level(1) == "high"
    assert suricata.severity_from_signature_level(2) == "medium"
    assert suricata.severity_from_signature_level(3) == "low"
    # Anything unexpected must degrade, never raise — an unknown severity must
    # not cost us the whole event.
    assert suricata.severity_from_signature_level(9) == "info"
    assert suricata.severity_from_signature_level(None) == "info"
    assert suricata.severity_from_signature_level("bogus") == "info"


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #


def test_normalize_event_flattens_an_alert_record():
    normalized = suricata.normalize_event(eve_alert())

    assert normalized is not None
    assert normalized["event_type"] == "alert"
    assert normalized["src_ip"] == "10.20.30.40"
    assert normalized["src_port"] == 44321
    assert normalized["dst_ip"] == "10.20.30.10"
    assert normalized["dst_port"] == 22
    assert normalized["proto"] == "TCP"
    assert normalized["app_proto"] == "ssh"
    assert normalized["signature"] == "ET SCAN Potential SSH Scan"
    assert normalized["signature_severity"] == 1
    assert normalized["occurred_at"].tzinfo is not None
    # The raw record is preserved verbatim as evidence.
    assert json.loads(normalized["payload"])["flow_id"] == 1234567890


def test_normalize_event_handles_flow_records_without_alert_block():
    normalized = suricata.normalize_event(
        eve_alert(event_type="flow", alert=None, app_proto="http", dest_port=8080)
    )

    assert normalized is not None
    assert normalized["event_type"] == "flow"
    assert normalized["signature"] is None
    assert normalized["signature_severity"] is None
    assert normalized["dst_port"] == 8080


def test_normalize_event_without_usable_timestamp_is_dropped():
    assert suricata.normalize_event(eve_alert(timestamp=None)) is None
    assert suricata.normalize_event({"event_type": "flow"}) is None


def test_normalize_events_skips_blank_and_malformed_lines():
    lines = [
        "",
        "   ",
        "{not json at all",
        json.dumps(eve_alert()),
        json.dumps({"no_timestamp": True}),
    ]
    events = suricata.normalize_events(lines)

    assert len(events) == 1
    assert events[0]["event_type"] == "alert"


def test_normalize_events_disambiguates_byte_identical_records():
    """Suricata can emit the same record twice; the unique event_id must hold."""
    line = json.dumps(eve_alert())
    events = suricata.normalize_events([line, line, line])

    assert len(events) == 3
    ids = [event["event_id"] for event in events]
    assert len(set(ids)) == 3
    assert ids[1].endswith("#1")
    assert ids[2].endswith("#2")


def test_event_id_is_stable_for_the_same_record():
    first = suricata.normalize_event(eve_alert())
    second = suricata.normalize_event(eve_alert())
    assert first["event_id"] == second["event_id"]

    # ...and differs when the signature (or the flow) differs.
    other = suricata.normalize_event(eve_alert(alert={"signature": "OTHER", "severity": 2}))
    assert other["event_id"] != first["event_id"]


# --------------------------------------------------------------------------- #
# Incremental tailing
# --------------------------------------------------------------------------- #


def _write(path, lines, mode="w"):
    with open(path, mode, encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")


def test_read_new_lines_reads_everything_from_a_fresh_file(tmp_path):
    path = tmp_path / "eve.json"
    _write(path, [json.dumps(eve_alert())])

    result = suricata.read_new_lines(path)

    assert not result.missing
    assert len(result.lines) == 1
    assert result.offset == path.stat().st_size
    assert result.inode == path.stat().st_ino


def test_read_new_lines_is_incremental(tmp_path):
    path = tmp_path / "eve.json"
    _write(path, [json.dumps(eve_alert())])

    first = suricata.read_new_lines(path)
    _write(path, [json.dumps(eve_alert(flow_id=2))], mode="a")
    second = suricata.read_new_lines(path, offset=first.offset, inode=first.inode)

    assert len(first.lines) == 1
    assert len(second.lines) == 1
    assert json.loads(second.lines[0])["flow_id"] == 2

    # Nothing new -> nothing returned, cursor unchanged.
    third = suricata.read_new_lines(path, offset=second.offset, inode=second.inode)
    assert third.lines == []
    assert third.offset == second.offset


def test_read_new_lines_does_not_consume_a_partial_record(tmp_path):
    path = tmp_path / "eve.json"
    _write(path, [json.dumps(eve_alert())])
    with open(path, "a", encoding="utf-8") as handle:
        handle.write('{"timestamp": "2026-09-21T03:14:16+00:00", "event_ty')  # half written

    result = suricata.read_new_lines(path)

    assert len(result.lines) == 1
    # The cursor stops on the last complete newline, so the partial record is
    # re-read (and completed) next cycle instead of being lost.
    assert result.offset < path.stat().st_size


def test_read_new_lines_resets_a_truncated_file(tmp_path):
    path = tmp_path / "eve.json"
    _write(path, [json.dumps(eve_alert())])
    first = suricata.read_new_lines(path)

    _write(path, [json.dumps(eve_alert(flow_id=99))])  # truncated, shorter file

    result = suricata.read_new_lines(path, offset=first.offset, inode=first.inode)

    assert len(result.lines) == 1
    assert json.loads(result.lines[0])["flow_id"] == 99


def test_read_new_lines_resets_after_rotation(tmp_path):
    path = tmp_path / "eve.json"
    _write(path, [json.dumps(eve_alert())])
    first = suricata.read_new_lines(path)

    rotated = tmp_path / "eve.json.new"
    _write(rotated, [json.dumps(eve_alert(flow_id=777))])
    rotated.replace(path)  # a genuinely new inode

    result = suricata.read_new_lines(path, offset=first.offset, inode=first.inode)

    assert result.rotated
    assert len(result.lines) == 1
    assert json.loads(result.lines[0])["flow_id"] == 777


def test_read_new_lines_reports_a_missing_file_without_raising(tmp_path):
    result = suricata.read_new_lines(tmp_path / "nope.json")

    assert result.missing
    assert result.lines == []


def test_suricata_accepts_events_older_than_now_only_once():
    """Guard against a regression where the tailer reused a stale offset."""
    now = datetime.now(timezone.utc)
    assert suricata.parse_timestamp((now - timedelta(seconds=5)).isoformat()) <= now
