from datetime import datetime

from pydantic import BaseModel, Field


class DocumentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    body: str = Field(min_length=1)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "title": "Quarterly Launch Plan",
                    "body": "Confidential launch notes for the Acme tenant.",
                }
            ]
        }
    }


class DocumentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    body: str | None = Field(default=None, min_length=1)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "title": "Updated Quarterly Launch Plan",
                    "body": "Updated document body.",
                }
            ]
        }
    }


class DocumentRead(BaseModel):
    id: str
    tenant_id: str
    owner_id: str
    title: str
    body: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ShareRequest(BaseModel):
    subject_type: str = Field(pattern="^(user|group)$")
    subject_id: str
    role: str = Field(pattern="^(owner|editor|commenter|viewer)$")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "subject_type": "user",
                    "subject_id": "00000000-0000-0000-0000-000000000002",
                    "role": "viewer",
                },
                {
                    "subject_type": "group",
                    "subject_id": "33333333-3333-3333-3333-333333333333",
                    "role": "commenter",
                },
            ]
        }
    }


class DelegatedLinkRequest(BaseModel):
    expires_in_seconds: int = Field(gt=0, le=604800)
    ip_address: str | None = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "expires_in_seconds": 300,
                    "ip_address": "203.0.113.10",
                },
                {
                    "expires_in_seconds": 900,
                },
            ]
        }
    }


class DelegatedLinkResponse(BaseModel):
    token: str
    caveats: list[str]

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "token": "MDAxZGxvY2F0aW9u...",
                    "caveats": [
                        "action = can_read",
                        "document_id = aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                        "expires_before = 1893456000",
                    ],
                }
            ]
        }
    }


class RelationshipRead(BaseModel):
    user: str
    relation: str
    object: str


class RelationshipInspection(BaseModel):
    document_id: str
    relationships: list[RelationshipRead]
