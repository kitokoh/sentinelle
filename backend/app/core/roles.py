"""Role model (v0.5, issue #12).

Three levels, each a strict superset of the previous one — that is the whole
authorisation model, and it is documented in ``docs/RBAC.md``:

======== ========= ========= =========
action    lecteur   analyste  admin
          (viewer)  (analyst) (admin)
======== ========= ========= =========
read      ✅         ✅        ✅
scans     ❌         ✅        ✅
users     ❌         ❌        ✅
======== ========= ========= =========

**Fail closed.** An unknown role is treated as ``viewer``, the weakest level.
A typo in the database must never grant more than it should.
"""

#: Ordered from the weakest to the strongest.
ROLES = ("viewer", "analyst", "admin")

#: Rank used for "at least this role" comparisons.
ROLE_ORDER = {role: index for index, role in enumerate(ROLES)}

#: Human labels, used in the audit log and the interface.
ROLE_LABELS = {"viewer": "Lecteur", "analyst": "Analyste", "admin": "Administrateur"}


def normalise(role: str | None) -> str:
    """Return a known role, downgrading anything unexpected to ``viewer``."""
    return role if role in ROLE_ORDER else "viewer"


def rank(role: str | None) -> int:
    return ROLE_ORDER[normalise(role)]


def role_at_least(role: str | None, minimum: str) -> bool:
    """Is ``role`` at least ``minimum``?"""
    return rank(role) >= rank(minimum)


def label(role: str | None) -> str:
    return ROLE_LABELS.get(normalise(role), normalise(role))
