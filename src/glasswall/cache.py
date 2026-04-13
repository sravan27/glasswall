from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


class JsonFileCache:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def get_json(self, key: str) -> Any | None:
        path = self._path_for(key)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None

        expires_at = payload.get("expires_at")
        if not isinstance(expires_at, str):
            return None
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        if expiry.astimezone(UTC) <= datetime.now(UTC):
            return None
        return payload.get("value")

    def set_json(self, key: str, value: Any, ttl_seconds: int) -> None:
        path = self._path_for(key)
        expires_at = datetime.now(UTC) + timedelta(seconds=ttl_seconds)
        payload = {
            "expires_at": expires_at.replace(microsecond=0).isoformat(),
            "value": value,
        }
        temp_path = path.with_suffix(".tmp")
        temp_path.write_text(json.dumps(payload))
        temp_path.replace(path)

    def _path_for(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.root / f"{digest}.json"
