from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.current_user import Principal, get_current_principal
from app.db.session import get_db
from app.models.audit import AuditLog
from app.schemas.audit import AuditLogRead

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get(
    "",
    response_model=list[AuditLogRead],
    summary="List tenant audit logs",
    description=(
        "Returns the latest authorization decisions for the caller's tenant. "
        "Rows include request ID, user, tenant, resource, action, decision, reason, and source."
    ),
    responses={
        200: {"description": "Recent tenant-scoped authorization decisions."},
        401: {"description": "Missing or invalid JWT."},
    },
)
def list_audit_logs(
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[AuditLogRead]:
    rows = db.scalars(
        select(AuditLog).where(AuditLog.tenant_id == principal.tenant_id).order_by(AuditLog.timestamp.desc()).limit(100)
    ).all()
    return [AuditLogRead.model_validate(row) for row in rows]
