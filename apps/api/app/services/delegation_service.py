from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, status
from pymacaroons import Macaroon, Verifier

from app.authz.models import Action, AuthorizationRequest
from app.authz.service import AuthorizationService
from app.config import Settings, get_settings


class DelegationService:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    def issue_read_token(
        self,
        *,
        issuer_user_id: str,
        issuer_tenant_id: str,
        document_id: str,
        expires_in_seconds: int,
        request_id: str,
        authz: AuthorizationService,
        request_ip: str | None,
        ip_address: str | None = None,
    ) -> tuple[str, list[str]]:
        authz.require(
            AuthorizationRequest(
                user_id=issuer_user_id,
                tenant_id=issuer_tenant_id,
                resource_type="document",
                resource_id=document_id,
                action=Action.READ,
                request_id=request_id,
            )
        )
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in_seconds)
        caveats = [
            f"action = {Action.READ.value}",
            f"document_id = {document_id}",
            f"tenant_id = {issuer_tenant_id}",
            f"issuer_user_id = {issuer_user_id}",
            f"expires_before = {int(expires_at.timestamp())}",
        ]
        bound_ip = ip_address or request_ip
        if not bound_ip:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unable to bind delegated token to caller IP")
        caveats.append(f"ip = {bound_ip}")
        macaroon = Macaroon(location=self.settings.macaroon_location, identifier=document_id, key=self.settings.macaroon_root_key)
        for caveat in caveats:
            macaroon.add_first_party_caveat(caveat)
        return macaroon.serialize(), caveats

    def verify_read_token(
        self,
        *,
        token: str,
        document_id: str,
        tenant_id: str,
        request_id: str,
        authz: AuthorizationService,
        request_ip: str | None,
    ) -> str:
        try:
            macaroon = Macaroon.deserialize(token)
            caveats = [c.caveat_id for c in macaroon.caveats]
            caveat_map = dict(c.split(" = ", 1) for c in caveats if " = " in c)
            expires = int(caveat_map["expires_before"])
            issuer_user_id = caveat_map["issuer_user_id"]
            verifier = Verifier()
            verifier.satisfy_exact(f"action = {Action.READ.value}")
            verifier.satisfy_exact(f"document_id = {document_id}")
            verifier.satisfy_exact(f"tenant_id = {tenant_id}")
            verifier.satisfy_exact(f"issuer_user_id = {issuer_user_id}")
            verifier.satisfy_exact(f"expires_before = {expires}")
            if datetime.now(UTC).timestamp() >= expires:
                raise ValueError("delegated token expired")
            if "ip" in caveat_map:
                if not request_ip or caveat_map["ip"] != request_ip:
                    raise ValueError("delegated token IP caveat failed")
                verifier.satisfy_exact(f"ip = {caveat_map['ip']}")
            verifier.verify(macaroon, self.settings.macaroon_root_key)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid delegated token") from exc

        authz.require(
            AuthorizationRequest(
                user_id=issuer_user_id,
                tenant_id=tenant_id,
                resource_type="document",
                resource_id=document_id,
                action=Action.READ,
                request_id=request_id,
                source="macaroon",
            )
        )
        return issuer_user_id
