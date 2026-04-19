from dataclasses import dataclass
from enum import StrEnum


class Action(StrEnum):
    READ = "can_read"
    EDIT = "can_edit"
    COMMENT = "can_comment"
    SHARE = "can_share"


class Role(StrEnum):
    OWNER = "owner"
    EDITOR = "editor"
    COMMENTER = "commenter"
    VIEWER = "viewer"


@dataclass(frozen=True)
class AuthorizationRequest:
    user_id: str
    tenant_id: str
    resource_type: str
    resource_id: str
    action: Action
    request_id: str
    source: str = "openfga"


@dataclass(frozen=True)
class AuthorizationDecision:
    allow: bool
    reason: str
    source: str

    @classmethod
    def allow_decision(cls, reason: str, source: str) -> "AuthorizationDecision":
        return cls(allow=True, reason=reason, source=source)

    @classmethod
    def deny_decision(cls, reason: str, source: str) -> "AuthorizationDecision":
        return cls(allow=False, reason=reason, source=source)

