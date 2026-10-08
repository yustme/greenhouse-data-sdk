"""Small synchronous API client with least-scope tokens, expiry and safe auth retries."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
import re
import threading
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

import httpx

from .config import ClientSettings

_PACKAGE = re.compile(r"^[a-z][a-z0-9-]*$")
_TABLE = re.compile(r"^[a-z][a-z0-9_]*$")


class CorporateError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass
class _Token:
    value: str = field(repr=False)
    expires_at: datetime


class CorporateClient:
    def __init__(self, api_url: str, service_token: str, *, settings: ClientSettings | None = None) -> None:
        parts = urlsplit(api_url)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("Corporate API URL must be an absolute HTTP(S) URL without credentials or query parameters")
        if not service_token or not service_token.strip():
            raise ValueError("Corporate service token is required")
        self.settings = settings if settings is not None else ClientSettings()
        self._api_url = api_url.rstrip("/")
        self._service_token = service_token
        self._tokens: dict[tuple[str, str], _Token] = {}
        self._lock = threading.RLock()
        self._http = httpx.Client(timeout=self.settings.timeout_seconds)

    @classmethod
    def from_env(cls, *, settings: ClientSettings | None = None, environ: Mapping[str, str] | None = None) -> CorporateClient:
        source = os.environ if environ is None else environ
        keys = ("GREENHOUSE_CORPORATE_API_URL", "GREENHOUSE_CORPORATE_TOKEN")
        missing = [key for key in keys if not source.get(key, "").strip()]
        if missing:
            raise ValueError("Missing managed environment variables: " + ", ".join(missing) + ". Share a Corporate package with this app and redeploy it.")
        return cls(source[keys[0]], source[keys[1]], settings=settings)

    def close(self) -> None:
        self._http.close()
        self._tokens.clear()

    def __enter__(self) -> CorporateClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _request(self, method: str, path: str, token: str, **kwargs: Any) -> Any:
        try:
            response = self._http.request(method, self._api_url + path, headers={"Authorization": "Bearer " + token}, **kwargs)
        except httpx.RequestError:
            raise CorporateError("Corporate API could not be reached; check the API address and network. Writes are not automatically retried.") from None
        if not response.is_success:
            try:
                detail = response.json().get("detail")
            except (ValueError, AttributeError):
                detail = None
            message = detail if isinstance(detail, str) else "Corporate API request failed"
            for secret in [self._service_token, token]:
                message = message.replace(secret, "[redacted]")
            hint = {401: "The credential expired or was revoked.", 403: "This operation is not shared with the app.",
                    404: "The package, table or requested permission is unavailable to the app.",
                    422: "Check the requested columns, values and operation limits."}.get(response.status_code, "")
            raise CorporateError(f"Corporate API {response.status_code}: {message}. {hint}".strip(), response.status_code)
        try:
            return response.json()
        except ValueError:
            raise CorporateError("Corporate API returned an invalid JSON response") from None

    def _token(self, package: str, permission: str, *, refresh: bool = False) -> str:
        if not _PACKAGE.fullmatch(package):
            raise ValueError("Invalid package name")
        key = (package, permission)
        with self._lock:
            cached = self._tokens.get(key)
            remaining = (cached.expires_at - datetime.now(timezone.utc)).total_seconds() if cached else None
            if not refresh and cached is not None and remaining is not None and remaining > self.settings.refresh_margin_seconds:
                return cached.value
            result = self._request("POST", "/access/token", self._service_token, json={"package": package, "permissions": [permission]})
            try:
                token = result["token"]
                expires = datetime.fromisoformat(result["expires_at"].replace("Z", "+00:00"))
                if not isinstance(token, str) or not token or expires.tzinfo is None or expires <= datetime.now(timezone.utc):
                    raise ValueError("Invalid token response")
            except (KeyError, TypeError, AttributeError, ValueError):
                raise CorporateError("Corporate API returned an invalid access token or expiration") from None
            self._tokens[key] = _Token(token, expires)
            return token

    def _data(self, package: str, table: str | None, operation: str, payload: dict[str, Any] | None = None) -> Any:
        if table is not None and not _TABLE.fullmatch(table):
            raise ValueError("Invalid table name")
        permission = {"tables": "read", "read": "read", "insert": "write", "update": "write", "delete": "delete"}[operation]
        token = self._token(package, permission)
        path = f"/data/{package}/tables" if table is None else f"/data/{package}/rows/{table}/{operation}"
        method = "GET" if table is None else "POST"
        kwargs = {} if table is None else {"json": payload}
        try:
            return self._request(method, path, token, **kwargs)
        except CorporateError as exc:
            if exc.status_code != 401:
                raise
        # A 401 is rejected before the server executes a row operation. Never retry network
        # failures, server failures or forbidden operations, which could duplicate writes.
        token = self._token(package, permission, refresh=True)
        return self._request(method, path, token, **kwargs)

    def tables(self, package: str) -> list[dict[str, Any]]:
        result = self._data(package, None, "tables")
        if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
            raise CorporateError("Corporate API returned invalid table metadata")
        return result

    def _row_result(self, result: Any) -> list[dict[str, Any]]:
        if not isinstance(result, dict) or not isinstance(result.get("rows"), list) or any(not isinstance(row, dict) for row in result["rows"]):
            raise CorporateError("Corporate API returned invalid row data")
        return result["rows"]

    def _count_result(self, result: Any) -> int:
        count = result.get("affected_rows") if isinstance(result, dict) else None
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise CorporateError("Corporate API returned an invalid affected row count")
        return count

    def read(self, package: str, table: str, *, columns: Sequence[str] | None = None, where: dict[str, Any] | None = None,
             limit: int | None = None, offset: int = 0) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {"offset": offset}
        if columns is not None:
            payload["columns"] = list(columns)
        if where is not None:
            payload["where"] = where
        if limit is not None:
            payload["limit"] = limit
        return self._row_result(self._data(package, table, "read", payload))

    def insert(self, package: str, table: str, rows: Sequence[dict[str, Any]]) -> int:
        return self._count_result(self._data(package, table, "insert", {"rows": list(rows)}))

    def update(self, package: str, table: str, values: dict[str, Any], where: dict[str, Any]) -> int:
        if not values or not where:
            raise ValueError("Update requires values and a nonempty equality filter")
        return self._count_result(self._data(package, table, "update", {"values": values, "where": where}))

    def delete(self, package: str, table: str, where: dict[str, Any]) -> int:
        if not where:
            raise ValueError("Delete requires a nonempty equality filter")
        return self._count_result(self._data(package, table, "delete", {"where": where}))
