"""nuclei JSONL parsing tests — the parser is pure, no nuclei binary needed."""

import asyncio
import json

import pytest

from app.services import scanner

# Two realistic nuclei v3 JSONL output lines: one critical, one info.
CRITICAL_LINE = json.dumps(
    {
        "template-id": "CVE-2021-41773",
        "template-url": "https://github.com/projectdiscovery/nuclei-templates",
        "info": {
            "name": "Apache HTTP Server 2.4.49 - Path Traversal",
            "severity": "critical",
            "tags": ["cve", "apache"],
        },
        "type": "http",
        "host": "http://192.168.56.10",
        "matched-at": "http://192.168.56.10/cgi-bin/.%2e/%2e%2e/etc/passwd",
        "matcher-name": "passwd-file",
        "timestamp": "2026-09-13T10:00:00Z",
    }
)

INFO_LINE = json.dumps(
    {
        "template-id": "apache-detect",
        "info": {"name": "Apache HTTP Server Detection", "severity": "info"},
        "type": "http",
        "host": "http://192.168.56.10",
        "matched-at": "http://192.168.56.10",
        "matcher-name": "server-header",
    }
)


def test_parse_critical_line():
    finding = scanner.parse_nuclei_line(CRITICAL_LINE)

    assert finding is not None
    assert finding["port"] == 0
    assert finding["protocol"] == "http"
    assert finding["service"] == "CVE-2021-41773"  # templateID preferred over name
    assert finding["version"] == ""
    assert finding["severity"] == "critical"
    assert "http://192.168.56.10/cgi-bin/.%2e/%2e%2e/etc/passwd" in finding["detail"]
    assert "passwd-file" in finding["detail"]


def test_parse_info_line():
    finding = scanner.parse_nuclei_line(INFO_LINE)

    assert finding is not None
    assert finding["service"] == "apache-detect"
    assert finding["severity"] == "info"
    assert finding["detail"] == "http://192.168.56.10 — server-header"


def test_parse_garbage_lines_return_none():
    assert scanner.parse_nuclei_line("") is None
    assert scanner.parse_nuclei_line("   \n") is None
    assert scanner.parse_nuclei_line("this is not json") is None
    assert scanner.parse_nuclei_line('["a", "list", "is", "not", "a", "match"]') is None


def test_parse_unknown_severity_degrades_to_info():
    line = json.dumps({"template-id": "x", "info": {"severity": "weird"}})
    finding = scanner.parse_nuclei_line(line)
    assert finding is not None
    assert finding["severity"] == "info"


def test_parse_falls_back_to_info_name_when_no_template_id():
    line = json.dumps({"info": {"name": "Generic Exposure", "severity": "low"}})
    finding = scanner.parse_nuclei_line(line)
    assert finding is not None
    assert finding["service"] == "Generic Exposure"
    assert finding["severity"] == "low"


class _FakeProcess:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self):
        return self._stdout, self._stderr


async def test_run_nuclei_scan_missing_binary_raises_runtimeerror(monkeypatch):
    async def _missing(*args, **kwargs):
        raise FileNotFoundError("nuclei")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _missing)

    with pytest.raises(RuntimeError, match="nuclei not installed"):
        await scanner.run_nuclei_scan("192.168.56.10", "quick")


async def test_run_nuclei_scan_nonzero_exit_raises_with_stderr_tail(monkeypatch):
    async def _failing(*args, **kwargs):
        return _FakeProcess(1, stderr=b"FATAL: could not load templates")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _failing)

    with pytest.raises(RuntimeError, match="exited with code 1: FATAL: could not load templates"):
        await scanner.run_nuclei_scan("192.168.56.10", "quick")


@pytest.mark.parametrize(
    "profile,expected_severities",
    [
        ("quick", "critical,high"),
        ("full", "critical,high,medium,low,info"),
    ],
)
async def test_run_nuclei_scan_parses_jsonl_and_filters_by_profile(
    monkeypatch, profile, expected_severities
):
    captured: dict = {}

    async def _ok(*args, **kwargs):
        captured["args"] = list(args)
        stdout = f"{CRITICAL_LINE}\n{INFO_LINE}\nnot-json-line\n".encode()
        return _FakeProcess(0, stdout=stdout)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _ok)

    findings = await scanner.run_nuclei_scan("192.168.56.10", profile)

    # Both valid lines parsed, the garbage line skipped.
    assert [f["severity"] for f in findings] == ["critical", "info"]
    # Profile-driven severity filter is passed to nuclei.
    flag_index = captured["args"].index("-severity")
    assert captured["args"][flag_index + 1] == expected_severities
    # Command shape per spec.
    assert captured["args"][0] == "nuclei"
    assert "192.168.56.10" in captured["args"]
