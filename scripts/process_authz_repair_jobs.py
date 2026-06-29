from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.authz.client import OpenFGAClient
from app.authz.repair import AuthzRepairService
from app.config import get_settings


def main() -> None:
    settings = get_settings()
    engine = create_engine(settings.database_url)
    with Session(engine) as db:
        processed = AuthzRepairService(db).process_pending_jobs(relationships=OpenFGAClient())
    print(f"Processed {processed} authorization repair jobs")


if __name__ == "__main__":
    main()
