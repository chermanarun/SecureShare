from pydantic import BaseModel


class HealthStatus(BaseModel):
    status: str
    service: str
    version: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "status": "ok",
                    "service": "SecureShare",
                    "version": "0.1.0",
                }
            ]
        }
    }


class ComponentStatus(BaseModel):
    status: str
    detail: str | None = None


class ReadinessStatus(BaseModel):
    status: str
    service: str
    version: str
    components: dict[str, ComponentStatus]

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "status": "ok",
                    "service": "SecureShare",
                    "version": "0.1.0",
                    "components": {
                        "postgres": {"status": "ok", "detail": "select 1 succeeded"},
                        "openfga": {"status": "ok", "detail": "health endpoint succeeded"},
                    },
                }
            ]
        }
    }
