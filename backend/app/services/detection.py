"""Declarative detection engine (v0.3, issue #2).

Turns a window of raw :class:`~app.models.sensor_event.SensorEvent` records into
exploitable detections. Three rule kinds ship by default, all defined in
``backend/rules/detection.yaml`` so they can be tuned without a code change:

  * ``port_scan``       — one source touching many distinct destination ports.
  * ``ssh_bruteforce``  — many SSH connection attempts, one source → one target.
  * ``beaconing``       — periodic connections to the same destination.

Design choices worth knowing:

* **No state in memory.** Evaluation is a pure function of the events handed to
  it, so the worker can crash/restart mid-window without losing a detection and
  the same function is trivially testable.
* **Confidence is a margin, not a probability.** It grows linearly with the
  threshold overshoot and saturates at 1.0 — see :func:`_threshold_confidence`.
* **One detection = one alert.** Both a *trigger* fixture (the rule fires) and a
  *non-trigger* fixture (it must stay silent) are pinned in the test-suite.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

import yaml

#: Shipped rule file: backend/rules/detection.yaml
DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "detection.yaml"

KINDS = ("port_scan", "ssh_bruteforce", "beaconing")

#: Destination port / application protocol that identifies SSH traffic in EVE.
SSH_PORT = 22
SSH_APP_PROTO = "ssh"


@dataclass(frozen=True)
class Rule:
    """A single declarative detection rule."""

    name: str
    kind: str
    severity: str = "medium"
    window_seconds: int = 60
    threshold: int = 10
    description: str = ""
    min_samples: int = 5
    max_interval_cv: float = 0.25


@dataclass
class Detection:
    """A rule that fired, ready to be persisted as an :class:`Alert`."""

    rule_name: str
    kind: str
    severity: str
    confidence: float
    detail: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    event_count: int = 0
    dedup_key: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Rule loading
# --------------------------------------------------------------------------- #

_BUILTIN_RULES = (
    Rule(
        name="port_scan",
        kind="port_scan",
        severity="high",
        window_seconds=60,
        threshold=20,
        description="One source touching more than 20 distinct destination ports within 60 s.",
    ),
    Rule(
        name="ssh_bruteforce",
        kind="ssh_bruteforce",
        severity="high",
        window_seconds=300,
        threshold=10,
        description="More than 10 SSH attempts from one source to one destination within 5 min.",
    ),
    Rule(
        name="beaconing",
        kind="beaconing",
        severity="medium",
        window_seconds=3600,
        threshold=5,
        min_samples=5,
        max_interval_cv=0.25,
        description="At least 5 connections to the same destination at a regular interval.",
    ),
)


def parse_rules(document: dict) -> list[Rule]:
    """Turn a parsed YAML document into :class:`Rule` objects.

    Raises ValueError on an unknown ``kind`` or a missing ``name`` — a silently
    ignored rule is a blind spot, so this fails loudly.
    """
    raw_rules = (document or {}).get("rules") or []
    rules: list[Rule] = []
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise ValueError(f"Rule #{index} must be a mapping, got {type(raw).__name__}")
        kind = str(raw.get("kind", "")).strip()
        if kind not in KINDS:
            raise ValueError(f"Rule #{index}: unknown kind {kind!r} (expected one of {KINDS})")
        name = str(raw.get("name", "")).strip()
        if not name:
            raise ValueError(f"Rule #{index}: 'name' is required")
        rules.append(
            Rule(
                name=name,
                kind=kind,
                severity=str(raw.get("severity", "medium")),
                window_seconds=int(raw.get("window_seconds", 60)),
                threshold=int(raw.get("threshold", 10)),
                description=str(raw.get("description", "")).strip(),
                min_samples=int(raw.get("min_samples", 5)),
                max_interval_cv=float(raw.get("max_interval_cv", 0.25)),
            )
        )
    if not rules:
        raise ValueError("No detection rule found in the document")
    return rules


def load_rules(path: Optional[str | Path] = None) -> list[Rule]:
    """Load rules from YAML, falling back to the packaged defaults."""
    candidate = Path(path) if path else DEFAULT_RULES_PATH
    try:
        with candidate.open("r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except FileNotFoundError:
        # A missing rule file degrades to the built-in set rather than disabling
        # detection: losing every rule silently would be the worst outcome.
        return list(_BUILTIN_RULES)
    return parse_rules(document)


# --------------------------------------------------------------------------- #
# Event access helpers — accept ORM objects *and* plain dicts (tests, fixtures)
# --------------------------------------------------------------------------- #


def _get(event: Any, name: str, default: Any = None) -> Any:
    if isinstance(event, dict):
        return event.get(name, default)
    return getattr(event, name, default)


def _as_datetime(value: Any) -> Optional[datetime]:
    """Coerce an EVE timestamp (or an ORM datetime) to an aware datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def _window(events: Iterable[Any], now: datetime, window_seconds: int) -> list[Any]:
    """Events whose timestamp falls inside the trailing window, oldest first."""
    cutoff = now - timedelta(seconds=window_seconds)
    kept = []
    for event in events:
        occurred = _as_datetime(_get(event, "occurred_at"))
        if occurred is None:
            continue
        if cutoff <= occurred <= now:
            kept.append((occurred, event))
    kept.sort(key=lambda pair: pair[0])
    return [event for _, event in kept]


def _threshold_confidence(count: int, threshold: int) -> float:
    """Confidence as the threshold overshoot, saturating at 1.0.

    A count exactly at ``threshold + 1`` gives ~0.5, a count at ``2 × threshold``
    gives 1.0. Documented so the number on screen means something.
    """
    if threshold <= 0:
        return 1.0
    return round(min(1.0, count / (2 * threshold)), 3)


def _dedup_key(kind: str, src_ip: Optional[str], dst_ip: Optional[str], dst_port: Optional[int]) -> str:
    return f"{kind}|{src_ip or '-'}|{dst_ip or '-'}|{dst_port if dst_port is not None else '-'}"


def _is_ssh(event: Any) -> bool:
    if _get(event, "dst_port") == SSH_PORT:
        return True
    return str(_get(event, "app_proto") or "").lower() == SSH_APP_PROTO


# --------------------------------------------------------------------------- #
# Rule evaluation
# --------------------------------------------------------------------------- #


def _eval_port_scan(rule: Rule, events: list[Any], now: datetime) -> list[Detection]:
    windowed = _window(events, now, rule.window_seconds)
    ports_by_source: dict[str, set[int]] = {}
    proto_by_source: dict[str, str] = {}
    for event in windowed:
        src = _get(event, "src_ip")
        dst_port = _get(event, "dst_port")
        if not src or dst_port is None:
            continue
        ports_by_source.setdefault(src, set()).add(int(dst_port))
        proto_by_source.setdefault(src, str(_get(event, "proto") or "tcp"))

    detections: list[Detection] = []
    for src, ports in ports_by_source.items():
        if len(ports) <= rule.threshold:
            continue
        confidence = _threshold_confidence(len(ports), rule.threshold)
        detections.append(
            Detection(
                rule_name=rule.name,
                kind=rule.kind,
                severity=rule.severity,
                confidence=confidence,
                detail=(
                    f"Port scan detected: {src} contacted {len(ports)} distinct destination "
                    f"ports within {rule.window_seconds}s (threshold {rule.threshold})."
                ),
                src_ip=src,
                dst_port=None,
                proto=proto_by_source.get(src, "tcp"),
                event_count=len(ports),
                dedup_key=_dedup_key(rule.kind, src, None, None),
                metadata={"distinct_ports": sorted(ports)[:50]},
            )
        )
    return detections


def _eval_ssh_bruteforce(rule: Rule, events: list[Any], now: datetime) -> list[Detection]:
    windowed = _window(events, now, rule.window_seconds)
    counters: dict[tuple[str, str], int] = {}
    for event in windowed:
        if not _is_ssh(event):
            continue
        src = _get(event, "src_ip")
        dst = _get(event, "dst_ip")
        if not src or not dst:
            continue
        counters[(src, dst)] = counters.get((src, dst), 0) + 1

    detections: list[Detection] = []
    for (src, dst), count in counters.items():
        if count <= rule.threshold:
            continue
        detections.append(
            Detection(
                rule_name=rule.name,
                kind=rule.kind,
                severity=rule.severity,
                confidence=_threshold_confidence(count, rule.threshold),
                detail=(
                    f"SSH brute force suspected: {count} connection attempts from {src} "
                    f"to {dst} within {rule.window_seconds}s (threshold {rule.threshold})."
                ),
                src_ip=src,
                dst_ip=dst,
                dst_port=SSH_PORT,
                proto="tcp",
                event_count=count,
                dedup_key=_dedup_key(rule.kind, src, dst, SSH_PORT),
                metadata={"attempts": count},
            )
        )
    return detections


def _eval_beaconing(rule: Rule, events: list[Any], now: datetime) -> list[Detection]:
    windowed = _window(events, now, rule.window_seconds)
    buckets: dict[tuple[str, str, int], list[datetime]] = {}
    for event in windowed:
        src = _get(event, "src_ip")
        dst = _get(event, "dst_ip")
        dst_port = _get(event, "dst_port")
        occurred = _as_datetime(_get(event, "occurred_at"))
        if not src or not dst or dst_port is None or occurred is None:
            continue
        buckets.setdefault((src, dst, int(dst_port)), []).append(occurred)

    detections: list[Detection] = []
    for (src, dst, dst_port), timestamps in buckets.items():
        samples = len(timestamps)
        if samples < max(rule.min_samples, rule.threshold):
            continue
        timestamps.sort()
        intervals = [
            (timestamps[i + 1] - timestamps[i]).total_seconds() for i in range(samples - 1)
        ]
        if not intervals:
            continue
        mean = sum(intervals) / len(intervals)
        if mean <= 0:
            continue
        variance = sum((value - mean) ** 2 for value in intervals) / len(intervals)
        deviation = variance**0.5
        coefficient = deviation / mean
        if coefficient > rule.max_interval_cv:
            continue
        detections.append(
            Detection(
                rule_name=rule.name,
                kind=rule.kind,
                severity=rule.severity,
                # Perfectly regular = 1.0; at the tolerance edge = ~0.75.
                confidence=round(min(1.0, max(0.0, 1.0 - coefficient)), 3),
                detail=(
                    f"Beaconing pattern: {samples} connections from {src} to {dst}:{dst_port} "
                    f"every ~{mean:.1f}s (interval variation {coefficient:.2f})."
                ),
                src_ip=src,
                dst_ip=dst,
                dst_port=dst_port,
                proto="tcp",
                event_count=samples,
                dedup_key=_dedup_key(rule.kind, src, dst, dst_port),
                metadata={
                    "samples": samples,
                    "mean_interval_seconds": round(mean, 3),
                    "interval_cv": round(coefficient, 4),
                },
            )
        )
    return detections


_EVALUATORS = {
    "port_scan": _eval_port_scan,
    "ssh_bruteforce": _eval_ssh_bruteforce,
    "beaconing": _eval_beaconing,
}


def evaluate(
    events: Sequence[Any],
    rules: Optional[Sequence[Rule]] = None,
    now: Optional[datetime] = None,
) -> list[Detection]:
    """Evaluate every rule against ``events`` and return the detections.

    ``events`` may be ORM rows or plain dicts having the ``SensorEvent`` field
    names. ``now`` is injectable so tests are deterministic.
    """
    active_rules = list(rules) if rules is not None else _BUILTIN_RULES
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)

    detections: list[Detection] = []
    for rule in active_rules:
        evaluator = _EVALUATORS.get(rule.kind)
        if evaluator is None:
            raise ValueError(f"Unknown rule kind: {rule.kind!r}")
        detections.extend(evaluator(rule, list(events), moment))
    return detections
