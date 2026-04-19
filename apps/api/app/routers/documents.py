from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.current_user import Principal, get_current_principal
from app.authz.models import Action, AuthorizationRequest
from app.authz.service import AuthorizationService
from app.authz.dependencies import get_authorization_service
from app.db.session import get_db
from app.schemas.documents import DocumentCreate, DocumentRead, DocumentUpdate, RelationshipInspection
from app.services.document_service import DocumentService

router = APIRouter(prefix="/documents", tags=["documents"])


@router.post(
    "",
    response_model=DocumentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a document",
    description=(
        "Creates a document in the caller's tenant, stores application data in PostgreSQL, "
        "and writes OpenFGA owner and tenant-parent relationships. Requires authentication."
    ),
    responses={
        201: {"description": "Document created and owner relationship written."},
        401: {"description": "Missing or invalid JWT."},
    },
)
def create_document(
    payload: DocumentCreate,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    authz: AuthorizationService = Depends(get_authorization_service),
) -> DocumentRead:
    service = DocumentService(db)
    document = service.create_document(tenant_id=principal.tenant_id, owner_id=principal.user_id, data=payload)
    for user, relation, object_ in service.owner_relationships(document=document):
        authz.relationships.write(user=user, relation=relation, object_=object_)
    return DocumentRead.model_validate(document)


@router.get(
    "/{document_id}",
    response_model=DocumentRead,
    summary="Read a document",
    description=(
        "Reads a document only after the shared authorization service verifies tenant boundary "
        "and OpenFGA returns `can_read` for the caller."
    ),
    responses={
        200: {"description": "Document returned."},
        401: {"description": "Missing or invalid JWT."},
        403: {"description": "OpenFGA denied access or the document is cross-tenant."},
        404: {"description": "Document not found after authorization succeeds."},
    },
)
def read_document(
    document_id: str,
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    authz: AuthorizationService = Depends(get_authorization_service),
) -> DocumentRead:
    authz.require(_authz_request(request, principal, document_id, Action.READ))
    document = DocumentService(db).get_document(document_id=document_id)
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    return DocumentRead.model_validate(document)


@router.patch(
    "/{document_id}",
    response_model=DocumentRead,
    summary="Edit a document",
    description=(
        "Updates a document only after the shared authorization service verifies tenant boundary "
        "and OpenFGA returns `can_edit` for the caller."
    ),
    responses={
        200: {"description": "Document updated."},
        401: {"description": "Missing or invalid JWT."},
        403: {"description": "OpenFGA denied edit access or the document is cross-tenant."},
        404: {"description": "Document not found after authorization succeeds."},
    },
)
def update_document(
    document_id: str,
    payload: DocumentUpdate,
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    authz: AuthorizationService = Depends(get_authorization_service),
) -> DocumentRead:
    authz.require(_authz_request(request, principal, document_id, Action.EDIT))
    service = DocumentService(db)
    document = service.get_document(document_id=document_id)
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    return DocumentRead.model_validate(service.update_document(document=document, data=payload))


@router.get(
    "/{document_id}/relationships",
    response_model=RelationshipInspection,
    summary="Inspect document relationships",
    description=(
        "Returns OpenFGA relationships for a document. This demo admin endpoint requires `can_share`, "
        "which is currently granted to document owners."
    ),
    responses={
        200: {"description": "Document relationships returned."},
        401: {"description": "Missing or invalid JWT."},
        403: {"description": "Caller is not allowed to inspect relationships."},
    },
)
def inspect_relationships(
    document_id: str,
    request: Request,
    principal: Principal = Depends(get_current_principal),
    authz: AuthorizationService = Depends(get_authorization_service),
) -> RelationshipInspection:
    authz.require(_authz_request(request, principal, document_id, Action.SHARE))
    return RelationshipInspection(document_id=document_id, relationships=authz.inspect_document(document_id=document_id))


def _authz_request(request: Request, principal: Principal, document_id: str, action: Action) -> AuthorizationRequest:
    return AuthorizationRequest(
        user_id=principal.user_id,
        tenant_id=principal.tenant_id,
        resource_type="document",
        resource_id=document_id,
        action=action,
        request_id=request.state.request_id,
    )
