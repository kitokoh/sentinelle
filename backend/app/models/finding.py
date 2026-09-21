"""Finding model — a single discovery attached to a scan.

Since v0.2 a finding can come from three sources (see `source`):
  * nmap   — open port / service discovered by the port scan (port > 0)
  * nuclei — template match from the nuclei vulnerability scanner (port == 0)
  * nvd    — CVE enrichment from the NVD API (port == 0, cve_id in `service`)
"""

from typing import Optional

from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel

from app.models.user import DEFAULT_ORG_ID


class Finding(SQLModel, table=True):
    __tablename__ = "findings"

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scans.id", index=True)
    #: Tenant boundary (v0.5, #15) — inherited from the scan.
    org_id: int = Field(default=DEFAULT_ORG_ID, foreign_key="organizations.id", index=True)
    port: int
    protocol: str = Field(default="tcp")
    service: str = Field(default="")
    version: str = Field(default="")
    severity: str = Field(default="info")  # info | low | medium | high | critical
    detail: str = Field(default="", sa_column=Column(Text))
    source: str = Field(default="nmap")  # nmap | nuclei | nvd
