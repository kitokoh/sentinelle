"""Thin async wrapper around nmap.

Runs `nmap -oX - --top-ports 100 -sV -T4 <target>` (profile "quick") or the
same with `-p-` instead of `--top-ports 100` (profile "full"), then parses
the XML written to stdout into structured finding dicts.

Only ever called by the worker, and only on targets whose scope_status is
"allowed" (enforced by the API layer + services/scope.py guardrail).
"""

import asyncio
import xml.etree.ElementTree as ET
from typing import Optional

# Services that are historically risky to expose; mapped to higher severity.
_RISKY_SERVICES = {
    "telnet": "high",
    "ftp": "high",
    "tftp": "high",
    "rlogin": "high",
    "rexec": "high",
    "rsh": "high",
    "microsoft-ds": "high",  # SMB
    "netbios-ssn": "medium",
    "smb": "high",
    "vnc": "medium",
    "rdp": "medium",
    "ms-wbt-server": "medium",  # nmap's name for RDP
    "mysql": "medium",
    "postgresql": "medium",
    "redis": "medium",
    "mongodb": "medium",
    "elasticsearch": "medium",
}


def classify_severity(service: str, port: int) -> str:
    """Map a discovered service to a rough severity rating."""
    name = (service or "").lower()
    if name in _RISKY_SERVICES:
        return _RISKY_SERVICES[name]
    if name:
        # Identified service, nothing obviously risky.
        return "low"
    return "info"


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parse nmap XML output into a list of finding dicts (open ports only)."""
    findings: list[dict] = []
    root = ET.fromstring(xml_text)

    for port_el in root.findall("./host/ports/port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue

        port = int(port_el.get("portid", "0"))
        protocol = port_el.get("protocol", "tcp")

        service_el: Optional[ET.Element] = port_el.find("service")
        service = ""
        version = ""
        if service_el is not None:
            service = service_el.get("name", "") or ""
            version = " ".join(
                part
                for part in (
                    service_el.get("product", "") or "",
                    service_el.get("version", "") or "",
                    service_el.get("extrainfo", "") or "",
                )
                if part
            )

        severity = classify_severity(service, port)
        detail = f"Open port {port}/{protocol}"
        if service:
            detail += f" — service: {service}"
        if version:
            detail += f" ({version})"

        findings.append(
            {
                "port": port,
                "protocol": protocol,
                "service": service,
                "version": version,
                "severity": severity,
                "detail": detail,
            }
        )

    return findings


async def run_nmap_scan(target_value: str, profile: str = "quick") -> list[dict]:
    """Run nmap against `target_value` and return structured findings.

    Raises RuntimeError with nmap's stderr when the scan fails.
    """
    port_args = ["-p-"] if profile == "full" else ["--top-ports", "100"]
    command = ["nmap", "-oX", "-", *port_args, "-sV", "-T4", target_value]

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        raise RuntimeError(
            f"nmap exited with code {process.returncode}: "
            f"{stderr.decode(errors='replace').strip()}"
        )

    return parse_nmap_xml(stdout.decode(errors="replace"))
