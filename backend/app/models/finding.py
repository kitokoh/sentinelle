"""Finding model — a single open port / service discovered by a scan."""

from typing import Optional

from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel


class Finding(SQLModel, table=True):
    __tablename__ = "findings"

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scans.id", index=True)
    port: int
    protocol: str = Field(default="tcp")
    service: str = Field(default="")
    version: str = Field(default="")
    severity: str = Field(default="info")  # info | low | medium | high | critical
    detail: str = Field(default="", sa_column=Column(Text))
