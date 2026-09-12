"""Re-export all SQLModel tables so `from app import models` registers them."""

from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User

__all__ = ["User", "Target", "Scan", "Finding"]
