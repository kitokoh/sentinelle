"""Threat-intel subsystem (v0.4).

Public surface:

* :mod:`~app.services.intel.misp` / :mod:`~app.services.intel.otx` — pull connectors.
* :mod:`~app.services.intel.feeds` — CERT advisory aggregation (RSS/Atom).
* :mod:`~app.services.intel.store` — normalisation-aware upserts (cross-source dedup).
* :mod:`~app.services.intel.correlation` — IoC ↔ alerts/findings matching.
* :mod:`~app.services.intel.overview` — read model for the Renseignement page.

Every connector degrades to "nothing to ingest" when its source is unreachable or
unconfigured: the platforms keeps working with whatever intel it already holds.
"""

from app.services.intel import correlation, feeds, misp, normalize, otx, overview, store

__all__ = ["correlation", "feeds", "misp", "normalize", "otx", "overview", "store"]
