from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.auth.passwords import hash_password
from app.authz.client import OpenFGAClient
from app.config import get_settings
from app.models.document import Document
from app.models.group import Group, GroupMember
from app.models.tenant import Tenant
from app.models.user import User

TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"
ALICE = "00000000-0000-0000-0000-000000000001"
BOB = "00000000-0000-0000-0000-000000000002"
EVE = "00000000-0000-0000-0000-000000000003"
DOC_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
DOC_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
GROUP_A = "33333333-3333-3333-3333-333333333333"


def main() -> None:
    settings = get_settings()
    engine = create_engine(settings.database_url)
    with Session(engine) as db:
        if db.scalar(select(Tenant).where(Tenant.id == TENANT_A)):
            print("Database seed already present")
        else:
            seed_database(db)
            print("Database seed inserted")
    try:
        seed_openfga()
        print("OpenFGA seed tuples written")
    except Exception as exc:
        print(f"OpenFGA seed skipped: {exc}")


def seed_database(db: Session) -> None:
    password = hash_password("password123")
    db.add_all(
        [
            Tenant(id=TENANT_A, slug="acme", name="Acme Corp"),
            Tenant(id=TENANT_B, slug="globex", name="Globex"),
            User(id=ALICE, tenant_id=TENANT_A, email="alice@example.com", display_name="Alice Owner", password_hash=password),
            User(id=BOB, tenant_id=TENANT_A, email="bob@example.com", display_name="Bob Viewer", password_hash=password),
            User(id=EVE, tenant_id=TENANT_B, email="eve@example.net", display_name="Eve OtherTenant", password_hash=password),
            Group(id=GROUP_A, tenant_id=TENANT_A, name="Acme Reviewers"),
            GroupMember(group_id=GROUP_A, user_id=BOB),
            Document(id=DOC_A, tenant_id=TENANT_A, owner_id=ALICE, title="Acme Plan", body="Confidential Acme launch plan."),
            Document(id=DOC_B, tenant_id=TENANT_B, owner_id=EVE, title="Globex Notes", body="Globex internal notes."),
        ]
    )
    db.commit()


def seed_openfga() -> None:
    tuples_path = Path(__file__).resolve().parents[1] / "infra" / "openfga" / "seed-tuples.json"
    data = json.loads(tuples_path.read_text())
    client = OpenFGAClient()
    for item in data["tuple_keys"]:
        client.write(user=item["user"], relation=item["relation"], object_=item["object"])


if __name__ == "__main__":
    main()

