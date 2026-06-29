from sqlalchemy import select
from sqlalchemy.orm import Session

from app.authz.client import RelationshipClient
from app.models.authz_repair_job import AuthzRepairJob


class AuthzRepairService:
    def __init__(self, db: Session):
        self.db = db

    def enqueue_delete_relationship(self, *, user: str, relation: str, object_: str, error: str) -> AuthzRepairJob:
        job = AuthzRepairJob(
            status="pending",
            operation="delete_relationship",
            user=user,
            relation=relation,
            object=object_,
            attempts=0,
            last_error=error,
        )
        self.db.add(job)
        self.db.commit()
        self.db.refresh(job)
        return job

    def process_pending_jobs(self, *, relationships: RelationshipClient, limit: int = 100) -> int:
        jobs = self.db.scalars(
            select(AuthzRepairJob)
            .where(AuthzRepairJob.status == "pending")
            .order_by(AuthzRepairJob.created_at.asc())
            .limit(limit)
        ).all()
        completed = 0
        for job in jobs:
            try:
                if job.operation == "delete_relationship":
                    relationships.delete(user=job.user, relation=job.relation, object_=job.object)
                else:
                    raise ValueError(f"Unsupported repair operation: {job.operation}")
                job.status = "completed"
                job.attempts += 1
                job.last_error = None
                completed += 1
            except Exception as exc:
                job.attempts += 1
                job.last_error = str(exc)
        self.db.commit()
        return completed
