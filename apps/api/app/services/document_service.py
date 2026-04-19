from sqlalchemy.orm import Session

from app.authz.client import document_ref, tenant_ref, user_ref
from app.authz.models import Role
from app.models.document import Document
from app.schemas.documents import DocumentCreate, DocumentUpdate


class DocumentService:
    def __init__(self, db: Session):
        self.db = db

    def create_document(self, *, tenant_id: str, owner_id: str, data: DocumentCreate) -> Document:
        document = Document(tenant_id=tenant_id, owner_id=owner_id, title=data.title, body=data.body)
        self.db.add(document)
        self.db.commit()
        self.db.refresh(document)
        return document

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

