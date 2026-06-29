from datetime import UTC, datetime, timedelta

import httpx
import jwt
from fastapi.testclient import TestClient

from app.auth.jwt import ALGORITHM, create_access_token
from app.authz.models import Role
from app.config import DEFAULT_JWT_SECRET, DEFAULT_MACAROON_ROOT_KEY, Settings, get_settings
from app.models.audit import AuditLog
from app.models.document import Document

from .conftest import ALICE, BOB, DOC_A, DOC_B, EVE, TENANT_A, auth_header


def test_owner_can_read_and_edit(client: TestClient, tokens: dict[str, str]) -> None:
    read = client.get(f"/documents/{DOC_A}", headers=auth_header(tokens["alice"]))
    assert read.status_code == 200
    edit = client.patch(f"/documents/{DOC_A}", json={"title": "Updated"}, headers=auth_header(tokens["alice"]))
    assert edit.status_code == 200
    assert edit.json()["title"] == "Updated"


def test_viewer_can_read_but_not_edit(client: TestClient, tokens: dict[str, str]) -> None:
    read = client.get(f"/documents/{DOC_A}", headers=auth_header(tokens["bob"]))
    assert read.status_code == 200
    edit = client.patch(f"/documents/{DOC_A}", json={"title": "Nope"}, headers=auth_header(tokens["bob"]))
    assert edit.status_code == 403


def test_idor_direct_object_tampering_denied(client: TestClient, tokens: dict[str, str]) -> None:
    response = client.get(f"/documents/{DOC_B}", headers=auth_header(tokens["bob"]))
    assert response.status_code == 403
    assert response.json()["detail"] == "cross-tenant resource access denied"


def test_cross_tenant_request_denied_even_if_tuple_exists(client: TestClient, tokens: dict[str, str], relationship_client) -> None:
    relationship_client.write(user=f"user:{BOB}", relation="viewer", object_=f"document:{DOC_B}")
    response = client.get(f"/documents/{DOC_B}", headers=auth_header(tokens["bob"]))
    assert response.status_code == 403


def test_cross_tenant_share_is_denied(client: TestClient, tokens: dict[str, str]) -> None:
    response = client.post(
        f"/documents/{DOC_A}/shares",
        json={"subject_type": "user", "subject_id": EVE, "role": "viewer"},
        headers=auth_header(tokens["alice"]),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Cross-tenant sharing is not allowed"


def test_owner_role_cannot_be_granted_via_share_api(client: TestClient, tokens: dict[str, str]) -> None:
    response = client.post(
        f"/documents/{DOC_A}/shares",
        json={"subject_type": "user", "subject_id": BOB, "role": "owner"},
        headers=auth_header(tokens["alice"]),
    )
    assert response.status_code == 422


def test_revoked_access_takes_effect_immediately_with_stale_jwt(client: TestClient, tokens: dict[str, str]) -> None:
    before = client.get(f"/documents/{DOC_A}", headers=auth_header(tokens["bob"]))
    assert before.status_code == 200
    revoke = client.request(
        "DELETE",
        f"/documents/{DOC_A}/shares",
        json={"subject_type": "user", "subject_id": BOB, "role": "viewer"},
        headers=auth_header(tokens["alice"]),
    )
    assert revoke.status_code == 204
    after = client.get(f"/documents/{DOC_A}", headers=auth_header(tokens["bob"]))
    assert after.status_code == 403


def test_malformed_jwt_is_rejected(client: TestClient) -> None:
    response = client.get(f"/documents/{DOC_A}", headers={"Authorization": "Bearer definitely-not-a-jwt"})
    assert response.status_code == 401


def test_weak_jwt_algorithm_is_rejected(client: TestClient) -> None:
    settings = get_settings()
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": ALICE,
            "tenant_id": TENANT_A,
            "email": "alice@example.com",
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
        key="",
        algorithm="none",
    )
    response = client.get(f"/documents/{DOC_A}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_delegated_token_allows_read(client: TestClient, tokens: dict[str, str]) -> None:
    issued = client.post(
        f"/documents/{DOC_A}/shares/delegated-link",
        json={"expires_in_seconds": 60},
        headers=auth_header(tokens["alice"]),
    )
    assert issued.status_code == 200
    response = client.get(f"/delegated/documents/{DOC_A}", headers={"x-delegation-token": issued.json()["token"]})
    assert response.status_code == 200


def test_expired_delegated_token_denied(client: TestClient, tokens: dict[str, str]) -> None:
    issued = client.post(
        f"/documents/{DOC_A}/shares/delegated-link",
        json={"expires_in_seconds": 1},
        headers=auth_header(tokens["alice"]),
    )
    assert issued.status_code == 200
    import time

    time.sleep(1.2)
    response = client.get(f"/delegated/documents/{DOC_A}", headers={"x-delegation-token": issued.json()["token"]})
    assert response.status_code == 403


def test_wrong_ip_delegated_token_denied(client: TestClient, tokens: dict[str, str]) -> None:
    issued = client.post(
        f"/documents/{DOC_A}/shares/delegated-link",
        json={"expires_in_seconds": 60, "ip_address": "203.0.113.10"},
        headers=auth_header(tokens["alice"]),
    )
    assert issued.status_code == 200
    response = client.get(f"/delegated/documents/{DOC_A}", headers={"x-delegation-token": issued.json()["token"]})
    assert response.status_code == 403


def test_delegated_token_revocation_uses_live_relationships(
    client: TestClient,
    tokens: dict[str, str],
    relationship_client,
) -> None:
    issued = client.post(
        f"/documents/{DOC_A}/shares/delegated-link",
        json={"expires_in_seconds": 60},
        headers=auth_header(tokens["alice"]),
    )
    assert issued.status_code == 200
    relationship_client.delete(user=f"user:{ALICE}", relation="owner", object_=f"document:{DOC_A}")
    response = client.get(f"/delegated/documents/{DOC_A}", headers={"x-delegation-token": issued.json()["token"]})
    assert response.status_code == 403


def test_login_rate_limit_and_failed_logins_are_audited(client: TestClient, db_session) -> None:
    for _ in range(5):
        response = client.post("/auth/login", json={"email": "alice@example.com", "password": "wrong-password"})
        assert response.status_code == 401
    limited = client.post("/auth/login", json={"email": "alice@example.com", "password": "wrong-password"})
    assert limited.status_code == 429
    rows = db_session.query(AuditLog).filter(AuditLog.resource == "auth:login:alice@example.com").all()
    assert len(rows) == 6
    assert rows[-1].reason == "rate limit exceeded"


def test_audit_logs_require_tenant_admin(client: TestClient, tokens: dict[str, str]) -> None:
    response = client.get("/audit", headers=auth_header(tokens["bob"]))
    assert response.status_code == 403
    assert response.json()["detail"] == "Tenant admin access required"


def test_tenant_admin_can_read_audit_logs(client: TestClient, tokens: dict[str, str]) -> None:
    client.get(f"/documents/{DOC_A}", headers=auth_header(tokens["alice"]))
    response = client.get("/audit", headers=auth_header(tokens["alice"]))
    assert response.status_code == 200
    rows = response.json()
    assert rows
    assert all(row["tenant_id"] == TENANT_A for row in rows)


def test_readiness_does_not_leak_raw_backend_errors(client: TestClient, monkeypatch) -> None:
    import app.routers.health as health_module

    def boom(*args, **kwargs):
        raise RuntimeError("tcp connect ECONNREFUSED postgres:5432 secret-details")

    monkeypatch.setattr(health_module, "httpx", type("FakeHttpx", (), {"get": staticmethod(boom)}))
    response = client.get("/readyz")
    assert response.status_code == 503
    payload = response.json()
    assert payload["components"]["openfga"]["detail"] == "authorization backend unavailable"
    assert "secret-details" not in str(payload)


def test_settings_reject_legacy_public_signing_keys() -> None:
    for kwargs in (
        {"environment": "dev", "jwt_secret": DEFAULT_JWT_SECRET, "macaroon_root_key": "strong-macaroon-root-key-value"},
        {"environment": "dev", "jwt_secret": "strong-jwt-secret-value", "macaroon_root_key": DEFAULT_MACAROON_ROOT_KEY},
    ):
        try:
            Settings(**kwargs)
        except Exception:
            continue
        raise AssertionError("Expected settings validation to fail for legacy public signing keys")


def test_dev_settings_generate_ephemeral_signing_keys() -> None:
    settings = Settings(environment="dev", jwt_secret=None, macaroon_root_key=None)
    assert settings.jwt_secret
    assert settings.macaroon_root_key
    assert settings.jwt_secret != DEFAULT_JWT_SECRET
    assert settings.macaroon_root_key != DEFAULT_MACAROON_ROOT_KEY
    assert len(settings.jwt_secret) >= 32
    assert len(settings.macaroon_root_key) >= 32


def test_document_create_rolls_back_if_openfga_write_fails(client: TestClient, db_session, relationship_client) -> None:
    original_write = relationship_client.write

    def failing_write(*, user: str, relation: str, object_: str) -> None:
        if relation == Role.OWNER.value:
            request = httpx.Request("POST", "http://openfga.test/stores/dev-store/write")
            response = httpx.Response(status_code=503, request=request)
            raise httpx.HTTPStatusError("openfga unavailable", request=request, response=response)
        original_write(user=user, relation=relation, object_=object_)

    relationship_client.write = failing_write
    token = client.post("/auth/login", json={"email": "alice@example.com", "password": "password123"}).json()["access_token"]
    response = client.post(
        "/documents",
        json={"title": "Should fail", "body": "rollback me"},
        headers=auth_header(token),
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "Authorization backend unavailable during document creation"
    assert db_session.query(Document).filter(Document.title == "Should fail").count() == 0


def test_every_authorization_decision_is_audited(client: TestClient, tokens: dict[str, str], db_session) -> None:
    client.get(f"/documents/{DOC_A}", headers=auth_header(tokens["alice"]))
    client.get(f"/documents/{DOC_B}", headers=auth_header(tokens["bob"]))
    rows = db_session.query(AuditLog).all()
    assert {row.decision for row in rows} >= {"allow", "deny"}
    assert all(row.request_id for row in rows)
    assert all(row.source in {"openfga", "macaroon", "auth"} for row in rows)
