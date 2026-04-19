from datetime import UTC, datetime, timedelta

import jwt
from fastapi.testclient import TestClient

from app.auth.jwt import ALGORITHM, create_access_token
from app.config import get_settings
from app.models.audit import AuditLog

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


def test_delegated_token_revocation_uses_live_relationships(client: TestClient, tokens: dict[str, str]) -> None:
    issued = client.post(
        f"/documents/{DOC_A}/shares/delegated-link",
        json={"expires_in_seconds": 60},
        headers=auth_header(tokens["alice"]),
    )
    assert issued.status_code == 200
    revoke_owner = client.request(
        "DELETE",
        f"/documents/{DOC_A}/shares",
        json={"subject_type": "user", "subject_id": ALICE, "role": "owner"},
        headers=auth_header(tokens["alice"]),
    )
    assert revoke_owner.status_code == 204
    response = client.get(f"/delegated/documents/{DOC_A}", headers={"x-delegation-token": issued.json()["token"]})
    assert response.status_code == 403


def test_every_authorization_decision_is_audited(client: TestClient, tokens: dict[str, str], db_session) -> None:
    client.get(f"/documents/{DOC_A}", headers=auth_header(tokens["alice"]))
    client.get(f"/documents/{DOC_B}", headers=auth_header(tokens["bob"]))
    rows = db_session.query(AuditLog).all()
    assert {row.decision for row in rows} >= {"allow", "deny"}
    assert all(row.request_id for row in rows)
    assert all(row.source in {"openfga", "macaroon"} for row in rows)

