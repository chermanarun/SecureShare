from fastapi import APIRouter, Depends, Request, status

from app.auth.current_user import Principal, get_current_principal
from app.authz.models import Action, AuthorizationRequest, Role
from app.authz.service import AuthorizationService
from app.authz.dependencies import get_authorization_service
from app.schemas.documents import DelegatedLinkRequest, DelegatedLinkResponse, ShareRequest
from app.services.delegation_service import DelegationService

router = APIRouter(prefix="/documents/{document_id}/shares", tags=["shares"])


@router.post(
    "",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Grant document access",
    description=(
        "Grants `owner`, `editor`, `commenter`, or `viewer` on a document to a user or group. "
        "The caller must pass the shared authorization service check for `can_share`."
    ),
    responses={
        204: {"description": "Relationship granted in OpenFGA."},
        401: {"description": "Missing or invalid JWT."},
        403: {"description": "Caller cannot share this document."},
    },
)
def share_document(
    document_id: str,
    payload: ShareRequest,
    request: Request,
    principal: Principal = Depends(get_current_principal),
    authz: AuthorizationService = Depends(get_authorization_service),
) -> None:
    authz.grant_document_role(
        actor_request=_share_request(request, principal, document_id),
        subject_type=payload.subject_type,
        subject_id=payload.subject_id,
        role=Role(payload.role),
    )


@router.delete(
    "",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke document access",
    description=(
        "Revokes a document relationship from a user or group in OpenFGA. "
        "Revocation takes effect on the next request without requiring JWT refresh."
    ),
    responses={
        204: {"description": "Relationship revoked in OpenFGA."},
        401: {"description": "Missing or invalid JWT."},
        403: {"description": "Caller cannot share this document."},
    },
)
def revoke_document_share(
    document_id: str,
    payload: ShareRequest,
    request: Request,
    principal: Principal = Depends(get_current_principal),
    authz: AuthorizationService = Depends(get_authorization_service),
) -> None:
    authz.revoke_document_role(
        actor_request=_share_request(request, principal, document_id),
        subject_type=payload.subject_type,
        subject_id=payload.subject_id,
        role=Role(payload.role),
    )


@router.post(
    "/delegated-link",
    response_model=DelegatedLinkResponse,
    summary="Create a delegated read link",
    description=(
        "Issues a Macaroon-style delegated read token with caveats for action, document, tenant, issuer, "
        "expiry, and caller IP address. The issuer must currently have `can_read`."
    ),
    responses={
        200: {"description": "Delegated token issued."},
        400: {"description": "Caller IP could not be bound into the delegated token."},
        401: {"description": "Missing or invalid JWT."},
        403: {"description": "Issuer cannot read this document."},
    },
)
def create_delegated_link(
    document_id: str,
    payload: DelegatedLinkRequest,
    request: Request,
    principal: Principal = Depends(get_current_principal),
    authz: AuthorizationService = Depends(get_authorization_service),
) -> DelegatedLinkResponse:
    token, caveats = DelegationService().issue_read_token(
        issuer_user_id=principal.user_id,
        issuer_tenant_id=principal.tenant_id,
        document_id=document_id,
        expires_in_seconds=payload.expires_in_seconds,
        request_ip=request.client.host if request.client else None,
        ip_address=payload.ip_address,
        request_id=request.state.request_id,
        authz=authz,
    )
    return DelegatedLinkResponse(token=token, caveats=caveats)


def _share_request(request: Request, principal: Principal, document_id: str) -> AuthorizationRequest:
    return AuthorizationRequest(
        user_id=principal.user_id,
        tenant_id=principal.tenant_id,
        resource_type="document",
        resource_id=document_id,
        action=Action.SHARE,
        request_id=request.state.request_id,
    )
