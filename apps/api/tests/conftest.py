from __future__ import annotations

import os
from collections.abc import Generator
from dataclasses import dataclass, field

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("SECURESHARE_ENVIRONMENT", "test")
os.environ.setdefault("SECURESHARE_JWT_SECRET", "test-jwt-secret-with-at-least-32-characters")
os.environ.setdefault("SECURESHARE_MACAROON_ROOT_KEY", "test-macaroon-root-key-with-at-least-32-characters")

from app.auth.passwords import hash_password
from app.authz.dependencies import get_relationship_client
from app.authz.models import Action
from app.config import get_settings
from app.db.session import get_db
from app.main import create_app
from app.models.base import Base
from app.models.document import Document
from app.models.group import Group, GroupMember
from app.models.tenant import Tenant
from app.models.user import User
from app.routers.auth import get_login_rate_limiter

TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"
ALICE = "00000000-0000-0000-0000-000000000001"
BOB = "00000000-0000-0000-0000-000000000002"
EVE = "00000000-0000-0000-0000-000000000003"
DOC_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
DOC_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
GROUP_A = "33333333-3333-3333-3333-333333333333"


@dataclass
class FakeRelationshipClient:
    tuples: set[tuple[str, str, str]] = field(default_factory=set)
    group_members: set[tuple[str, str]] = field(default_factory=set)

    def check(self, *, user: str, relation: str, object_: str) -> bool:
        direct_relations = {
            Action.READ.value: {"owner", "editor", "commenter", "viewer"},
            Action.EDIT.value: {"owner", "editor"},
            Action.COMMENT.value: {"owner", "editor", "commenter"},
            Action.SHARE.value: {"owner"},
        }.get(relation, {relation})
        for candidate in direct_relations:
            if (user, candidate, object_) in self.tuples:
                return True
            for group_id, member_user in self.group_members:
                if member_user == user and (f"group:{group_id}#member", candidate, object_) in self.tuples:
                    return True
        return False

    def write(self, *, user: str, relation: str, object_: str) -> None:
        self.tuples.add((user, relation, object_))

    def delete(self, *, user: str, relation: str, object_: str) -> None:
        self.tuples.discard((user, relation, object_))

    def list_object_relations(self, *, object_: str) -> list[dict[str, str]]:
        return [{"user": user, "relation": relation, "object": obj} for user, relation, obj in sorted(self.tuples) if obj == object_]


@pytest.fixture()
def relationship_client() -> FakeRelationshipClient:
    fake = FakeRelationshipClient()
    fake.group_members.add((GROUP_A, f"user:{BOB}"))
    fake.write(user=f"user:{ALICE}", relation="owner", object_=f"document:{DOC_A}")
    fake.write(user=f"user:{BOB}", relation="viewer", object_=f"document:{DOC_A}")
    fake.write(user=f"user:{EVE}", relation="owner", object_=f"document:{DOC_B}")
    return fake


@pytest.fixture()
def db_session() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    session = TestingSession()
    seed(session)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db_session: Session, relationship_client: FakeRelationshipClient) -> Generator[TestClient, None, None]:
    get_settings.cache_clear()
    get_login_rate_limiter.cache_clear()
    app = create_app()

    def override_db() -> Generator[Session, None, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_relationship_client] = lambda: relationship_client
    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()
    get_login_rate_limiter.cache_clear()


@pytest.fixture(autouse=True)
def reset_login_rate_limiter() -> Generator[None, None, None]:
    get_settings.cache_clear()
    get_login_rate_limiter.cache_clear()
    limiter = get_login_rate_limiter()
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture()
def tokens(client: TestClient) -> dict[str, str]:
    return {
        "alice": login(client, "alice@example.com"),
        "bob": login(client, "bob@example.com"),
        "eve": login(client, "eve@example.net"),
    }


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def login(client: TestClient, email: str) -> str:
    response = client.post("/auth/login", json={"email": email, "password": "password123"})
    assert response.status_code == 200
    return response.json()["access_token"]


def seed(db: Session) -> None:
    password = hash_password("password123")
    db.add_all(
        [
            Tenant(id=TENANT_A, slug="acme", name="Acme Corp"),
            Tenant(id=TENANT_B, slug="globex", name="Globex"),
            User(id=ALICE, tenant_id=TENANT_A, email="alice@example.com", display_name="Alice", password_hash=password),
            User(id=BOB, tenant_id=TENANT_A, email="bob@example.com", display_name="Bob", password_hash=password),
            User(id=EVE, tenant_id=TENANT_B, email="eve@example.net", display_name="Eve", password_hash=password),
            Group(id=GROUP_A, tenant_id=TENANT_A, name="Reviewers"),
            GroupMember(group_id=GROUP_A, user_id=BOB),
            Document(id=DOC_A, tenant_id=TENANT_A, owner_id=ALICE, title="Acme Plan", body="secret"),
            Document(id=DOC_B, tenant_id=TENANT_B, owner_id=EVE, title="Globex Plan", body="other tenant"),
        ]
    )
    db.commit()
