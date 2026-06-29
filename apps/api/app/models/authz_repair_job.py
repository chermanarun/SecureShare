from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_str


class AuthzRepairJob(Base, TimestampMixin):
    __tablename__ = "authz_repair_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending", index=True)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    user: Mapped[str] = mapped_column(String(240), nullable=False)
    relation: Mapped[str] = mapped_column(String(80), nullable=False)
    object: Mapped[str] = mapped_column(String(240), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
