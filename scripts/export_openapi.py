from __future__ import annotations

import json
from pathlib import Path

from app.main import create_app


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    output_path = root / "docs" / "openapi.json"
    app = create_app()
    output_path.write_text(json.dumps(app.openapi(), indent=2) + "\n")
    print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()

