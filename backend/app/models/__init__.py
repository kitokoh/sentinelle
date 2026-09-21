"""Re-export all SQLModel tables so `from app import models` registers them."""

from app.models.alert import Alert, utcnow
from app.models.finding import Finding
from app.models.ingest_state import IngestState
from app.models.scan import Scan
from app.models.sensor_event import SensorEvent
from app.models.target import Target
from app.models.user import User

__all__ = [
    "User",
    "Target",
    "Scan",
    "Finding",
    "Alert",
    "SensorEvent",
    "IngestState",
    # Canonical UTC "now" helper, re-exported so callers need only one import.
    "utcnow",
]
