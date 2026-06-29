import httpx
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.authz.repair import AuthzRepairService
from app.authz.client import RelationshipClient, document_ref, tenant_ref, user_ref
from app.authz.models import Role
from app.models.document import Document
from app.schemas.documents import DocumentCreate, DocumentUpdate


class DocumentService:
    def __init__(self, db: Session):
        self.db = db

    def create_document_with_relationships(
        self,
        *,
        tenant_id: str,
        owner_id: str,
        data: DocumentCreate,
        relationships: RelationshipClient,
    ) -> Document:
        document = Document(tenant_id=tenant_id, owner_id=owner_id, title=data.title, body=data.body)
        self.db.add(document)
        self.db.flush()
        written_relationships: list[tuple[str, str, str]] = []
        try:
            for user, relation, object_ in self.owner_relationships(document=document):
                relationships.write(user=user, relation=relation, object_=object_)
                written_relationships.append((user, relation, object_))
            self.db.commit()
            self.db.refresh(document)
            return document
        except httpx.HTTPError as exc:
            self.db.rollback()
            self._best_effort_relationship_cleanup(relationships, written_relationships)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authorization backend unavailable during document creation",
            ) from exc
        except Exception:
            self.db.rollback()
            self._best_effort_relationship_cleanup(relationships, written_relationships)
            raise

    def update_document(self, *, document: Document, data: DocumentUpdate) -> Document:
        if data.title is not None:
            document.title = data.title
        if data.body is not None:
            document.body = data.body
        self.db.add(document)
        self.db.commit()
        self.db.refresh(document)
        return document

    def get_document(self, *, document_id: str) -> Document | None:
        return self.db.get(Document, document_id)

    @staticmethod
    def owner_relationships(*, document: Document) -> list[tuple[str, str, str]]:
        return [
            (user_ref(document.owner_id), Role.OWNER.value, document_ref(document.id)),
            (document_ref(document.id), "parent", tenant_ref(document.tenant_id)),
        ]

    def _best_effort_relationship_cleanup(
        self,
        relationships: RelationshipClient,
        written_relationships: list[tuple[str, str, str]],
    ) -> None:
        repair = AuthzRepairService(self.db)
        for user, relation, object_ in reversed(written_relationships):
            try:
                relationships.delete(user=user, relation=relation, object_=object_)
            except Exception as exc:
                repair.enqueue_delete_relationship(
                    user=user,
                    relation=relation,
                    object_=object_,
                    error=str(exc),
                )
