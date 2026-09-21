"""AuditLog — who did what, when (v0.5, issue #13).

Written automatically by the middleware in ``app/main.py`` for every mutating
API request, not by hand in each route. Two consequences worth stating:

* **No route can forget to log.** Forgetting is the default failure mode of
  hand-written audit trails; centralising it removes the possibility.
* **No request body is ever stored.** Passwords and tokens travel in bodies, and
  an audit trail that captures them becomes a liability. Only the method, the
  path, the status, the actor and the source IP are recorded — plus an optional
  short ``detail`` a route may attach when the *meaning* of the change matters
  (for instance a role transition).

The trail is append-only: there is no update or delete route, and the retention
purge deliberately does **not** touch it.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditLog(SQLModel, table=True):
    __tablename__ = "audit_logs"

    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=utcnow, index=True)

    #: Resolved from the bearer token when the request carried one.
    actor_id: Optional[int] = Field(default=None, index=True)
    actor_email: Optional[str] = Field(default=None, index=True)
    #: Organisation the actor belonged to at the time of the action.
    org_id: Optional[int] = Field(default=None, index=True)

    #: ``<entity>.<verb>[.<sub>]`` — e.g. ``targets.create``, ``scans.create``.
    action: str = Field(index=True)
    method: str
    path: str
    status_code: int
    entity: Optional[str] = Field(default=None, index=True)
    entity_id: Optional[int] = Field(default=None, index=True)

    ip: Optional[str] = Field(default=None, index=True)
    user_agent: Optional[str] = None
    detail: str = Field(default="", sa_column=Column(Text))
