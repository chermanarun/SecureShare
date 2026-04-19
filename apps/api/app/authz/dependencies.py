from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.authz.client import OpenFGAClient, RelationshipClient
from app.authz.service import AuthorizationService
from app.db.session import get_db


def get_relationship_client() -> RelationshipClient:
    return OpenFGAClient()


def get_authorization_service(
    request: Request,
    db: Session = Depends(get_db),
    relationships: RelationshipClient = Depends(get_relationship_client),
) -> AuthorizationService:
    request.state.authz_service = AuthorizationService(db=db, relationships=relationships)
    return request.state.authz_service

