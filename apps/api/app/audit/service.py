from sqlalchemy.orm import Session

from app.models.audit import AuditLog


class AuditService:
    def __init__(self, db: Session):
        self.db = db

    def record(
        self,
        *,
        request_id: str,
        user_id: str | None,
        tenant_id: str | None,
        resource: str,
        action: str,
        allow: bool,
        reason: str,
        source: str,
    ) -> AuditLog:
        entry = AuditLog(
            request_id=request_id,
            user_id=user_id,
            tenant_id=tenant_id,
            resource=resource,
            action=action,
            decision="allow" if allow else "deny",
            reason=reason,
            source=source,
        )
        self.db.add(entry)
        self.db.commit()
        return entry

