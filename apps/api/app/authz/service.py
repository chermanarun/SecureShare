from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.audit.service import AuditService
from app.authz.client import ACTION_TO_RELATION, ROLE_TO_RELATION, RelationshipClient, document_ref, group_member_ref, user_ref
from app.authz.models import AuthorizationDecision, AuthorizationRequest, Role
from app.models.document import Document


class AuthorizationService:
    def __init__(self, *, db: Session, relationships: RelationshipClient):
        self.db = db
        self.relationships = relationships
        self.audit = AuditService(db)

    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision:
        document = self.db.get(Document, request.resource_id) if request.resource_type == "document" else None
        if document is None:
            decision = AuthorizationDecision.deny_decision("resource not found", request.source)
            self._audit(request, decision)
            return decision
        if document.tenant_id != request.tenant_id:
            decision = AuthorizationDecision.deny_decision("cross-tenant resource access denied", request.source)
            self._audit(request, decision)
            return decision

        allowed = self.relationships.check(
            user=user_ref(request.user_id),
            relation=ACTION_TO_RELATION[request.action],
            object_=document_ref(document.id),
        )
        decision = (
            AuthorizationDecision.allow_decision("allowed by relationship graph", request.source)
            if allowed
            else AuthorizationDecision.deny_decision("relationship check denied", request.source)
        )
        self._audit(request, decision)
        return decision

    def require(self, request: AuthorizationRequest) -> None:
        decision = self.authorize(request)
        if not decision.allow:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    def grant_document_role(self, *, actor_request: AuthorizationRequest, subject_type: str, subject_id: str, role: Role) -> None:
        self.require(actor_request)
        subject = user_ref(subject_id) if subject_type == "user" else group_member_ref(subject_id)
        self.relationships.write(user=subject, relation=ROLE_TO_RELATION[role], object_=document_ref(actor_request.resource_id))

    def revoke_document_role(self, *, actor_request: AuthorizationRequest, subject_type: str, subject_id: str, role: Role) -> None:
        self.require(actor_request)
        subject = user_ref(subject_id) if subject_type == "user" else group_member_ref(subject_id)
        self.relationships.delete(user=subject, relation=ROLE_TO_RELATION[role], object_=document_ref(actor_request.resource_id))

    def inspect_document(self, *, document_id: str) -> list[dict[str, str]]:
        return self.relationships.list_object_relations(object_=document_ref(document_id))

    def _audit(self, request: AuthorizationRequest, decision: AuthorizationDecision) -> None:
        self.audit.record(
            request_id=request.request_id,
            user_id=request.user_id,
            tenant_id=request.tenant_id,
            resource=f"{request.resource_type}:{request.resource_id}",
            action=request.action.value,
            allow=decision.allow,
            reason=decision.reason,
            source=decision.source,
        )
