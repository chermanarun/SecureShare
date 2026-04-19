from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.authz.service import AuthorizationService
from app.authz.dependencies import get_authorization_service
from app.db.session import get_db
from app.schemas.documents import DocumentRead
from app.services.delegation_service import DelegationService
from app.services.document_service import DocumentService

router = APIRouter(prefix="/delegated", tags=["delegated"])


@router.get(
    "/documents/{document_id}",
    response_model=DocumentRead,
    summary="Read a document using a delegated token",
    description=(
        "Reads a document with an `x-delegation-token` Macaroon. The endpoint validates caveats "
        "and performs a live OpenFGA `can_read` check for the issuing user before returning data."
    ),
    responses={
        200: {"description": "Document returned through delegated access."},
        403: {"description": "Delegated token is expired, malformed, caveat-violating, or issuer access was revoked."},
        404: {"description": "Document not found."},
    },
)
def read_delegated_document(
    document_id: str,
    request: Request,
    token: str = Header(alias="x-delegation-token"),
    db: Session = Depends(get_db),
    authz: AuthorizationService = Depends(get_authorization_service),
) -> DocumentRead:
    document = DocumentService(db).get_document(document_id=document_id)
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    DelegationService().verify_read_token(
        token=token,
        document_id=document_id,
        tenant_id=document.tenant_id,
        request_id=request.state.request_id,
        authz=authz,
        request_ip=request.client.host if request.client else None,
    )
    return DocumentRead.model_validate(document)
