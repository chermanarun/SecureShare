from __future__ import annotations

import json
from pathlib import Path

import httpx

from app.config import get_settings


def main() -> None:
    settings = get_settings()
    base_url = settings.openfga_api_url.rstrip("/")
    root = Path(__file__).resolve().parents[1]
    model = json.loads((root / "infra" / "openfga" / "model.json").read_text())
    headers = {"content-type": "application/json"}
    if settings.openfga_api_token:
        headers["authorization"] = f"Bearer {settings.openfga_api_token}"

    with httpx.Client(base_url=base_url, timeout=10.0) as client:
        store_response = client.post("/stores", json={"name": "SecureShare Dev"}, headers=headers)
        store_response.raise_for_status()
        store_id = store_response.json()["id"]
        model_response = client.post(f"/stores/{store_id}/authorization-models", json=model, headers=headers)
        model_response.raise_for_status()
        model_id = model_response.json()["authorization_model_id"]

    print("OpenFGA bootstrap complete")
    print(f"SECURESHARE_OPENFGA_STORE_ID={store_id}")
    print(f"SECURESHARE_OPENFGA_AUTHORIZATION_MODEL_ID={model_id}")


if __name__ == "__main__":
    main()
