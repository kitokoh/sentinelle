"""Seed script: demo admin user + one sample in-scope target.

Run from the backend/ directory:  python seed.py
"""

import asyncio

from sqlmodel import select

from app.core.security import hash_password
from app.db import async_session, init_db
from app.models import Target, User
from app.services.scope import validate_target

DEMO_EMAIL = "admin@sentinelle.local"
DEMO_PASSWORD = "Sentinelle2026!"
SAMPLE_TARGET_VALUE = "192.168.56.10"


async def main() -> None:
    await init_db()
    async with async_session() as session:
        user = (
            await session.exec(select(User).where(User.email == DEMO_EMAIL))
        ).first()
        if user is None:
            user = User(
                email=DEMO_EMAIL,
                hashed_password=hash_password(DEMO_PASSWORD),
                role="admin",
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            print(f"Created demo user: {DEMO_EMAIL} / {DEMO_PASSWORD}")
        else:
            print(f"Demo user already exists: {DEMO_EMAIL}")

        target = (
            await session.exec(
                select(Target).where(
                    Target.value == SAMPLE_TARGET_VALUE, Target.owner_id == user.id
                )
            )
        ).first()
        if target is None:
            scope_status = validate_target(SAMPLE_TARGET_VALUE, "ip", None)
            target = Target(
                name="Demo lab VM",
                value=SAMPLE_TARGET_VALUE,
                kind="ip",
                scope_status=scope_status,
                owner_id=user.id,
            )
            session.add(target)
            await session.commit()
            print(f"Created sample target: {SAMPLE_TARGET_VALUE} (scope: {scope_status})")
        else:
            print(f"Sample target already exists: {SAMPLE_TARGET_VALUE}")


if __name__ == "__main__":
    asyncio.run(main())
