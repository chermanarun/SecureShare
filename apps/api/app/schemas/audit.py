from datetime import datetime

from pydantic import BaseModel


class AuditLogRead(BaseModel):
    id: str
    timestamp: datetime
    request_id: str
    user_id: str | None
    tenant_id: str | None
    resource: str
    action: str
    decision: str
    reason: str
    source: str

    model_config = {"from_attributes": True}

