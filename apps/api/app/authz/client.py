from typing import Any, Protocol

import httpx

from app.authz.models import Action, Role
from app.config import Settings, get_settings


class RelationshipClient(Protocol):
    def check(self, *, user: str, relation: str, object_: str) -> bool: ...
    def write(self, *, user: str, relation: str, object_: str) -> None: ...
    def delete(self, *, user: str, relation: str, object_: str) -> None: ...
    def list_object_relations(self, *, object_: str) -> list[dict[str, str]]: ...


class OpenFGAClient:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.base_url = self.settings.openfga_api_url.rstrip("/")

    @property
    def _store_path(self) -> str:
        return f"/stores/{self.settings.openfga_store_id}"

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self.settings.openfga_authorization_model_id:
            headers["authorization-model-id"] = self.settings.openfga_authorization_model_id
        if self.settings.openfga_api_token:
            headers["authorization"] = f"Bearer {self.settings.openfga_api_token}"
        return headers

    def check(self, *, user: str, relation: str, object_: str) -> bool:
        payload: dict[str, Any] = {"tuple_key": {"user": user, "relation": relation, "object": object_}}
        with httpx.Client(base_url=self.base_url, timeout=5.0) as client:
            response = client.post(f"{self._store_path}/check", json=payload, headers=self._headers())
            response.raise_for_status()
            data = response.json()
        return bool(data.get("allowed"))

    def write(self, *, user: str, relation: str, object_: str) -> None:
        payload = {"writes": {"tuple_keys": [{"user": user, "relation": relation, "object": object_}]}}
        with httpx.Client(base_url=self.base_url, timeout=5.0) as client:
            response = client.post(f"{self._store_path}/write", json=payload, headers=self._headers())
            response.raise_for_status()

    def delete(self, *, user: str, relation: str, object_: str) -> None:
        payload = {"deletes": {"tuple_keys": [{"user": user, "relation": relation, "object": object_}]}}
        with httpx.Client(base_url=self.base_url, timeout=5.0) as client:
            response = client.post(f"{self._store_path}/write", json=payload, headers=self._headers())
            response.raise_for_status()

    def list_object_relations(self, *, object_: str) -> list[dict[str, str]]:
        body = {"tuple_key": {"object": object_}}
        with httpx.Client(base_url=self.base_url, timeout=5.0) as client:
            response = client.post(f"{self._store_path}/read", json=body, headers=self._headers())
            response.raise_for_status()
            data = response.json()
        return [
            {"user": item["key"]["user"], "relation": item["key"]["relation"], "object": item["key"]["object"]}
            for item in data.get("tuples", [])
        ]


def user_ref(user_id: str) -> str:
    return f"user:{user_id}"


def group_ref(group_id: str) -> str:
    return f"group:{group_id}"


def group_member_ref(group_id: str) -> str:
    return f"group:{group_id}#member"


def tenant_ref(tenant_id: str) -> str:
    return f"tenant:{tenant_id}"


def document_ref(document_id: str) -> str:
    return f"document:{document_id}"


ROLE_TO_RELATION = {
    Role.OWNER: "owner",
    Role.EDITOR: "editor",
    Role.COMMENTER: "commenter",
    Role.VIEWER: "viewer",
}

ACTION_TO_RELATION = {
    Action.READ: "can_read",
    Action.EDIT: "can_edit",
    Action.COMMENT: "can_comment",
    Action.SHARE: "can_share",
}
