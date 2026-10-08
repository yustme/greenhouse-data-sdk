"""SDK protocol behavior over a real localhost HTTP transport, without production changes."""
import json
import socket
import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from greenhouse_data import CorporateClient, CorporateError, ClientSettings

SERVICE = "service-credential"


@pytest.fixture
def endpoint():
    class Recorded(list):
        token_answers = None
    requests, responses = Recorded(), deque()
    requests.token_answers = deque()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            self.respond()
        def do_POST(self):
            self.respond()
        def respond(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append({"method": self.command, "path": self.path, "auth": self.headers.get("Authorization"), "user_session": self.headers.get("X-Greenhouse-User-Session"), "body": json.loads(body) if body else None})
            if self.path.endswith("/access/token"):
                answer = {"token": f"scope-{len(requests)}", "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()}
                status = 200
                if requests.token_answers:
                    status, answer = requests.token_answers.popleft()
            else:
                status, answer = responses.popleft() if responses else (200, {"rows": [{"id": 1}]})
            if answer is None:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            raw = answer if isinstance(answer, bytes) else json.dumps(answer).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers(); self.wfile.write(raw)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True); thread.start()
    yield f"http://127.0.0.1:{server.server_port}/api/corporate", requests, responses
    server.shutdown(); thread.join(); server.server_close()


def test_least_scope_exchange_cache_and_structured_payloads(endpoint):
    url, requests, responses = endpoint
    responses.extend([(200, [{"name": "entries"}]), (200, {"rows": [{"id": 1}]}), (200, {"affected_rows": 2}), (200, {"affected_rows": 1}), (200, {"affected_rows": 1})])
    with CorporateClient(url, SERVICE) as client:
        assert client.tables("finance") == [{"name": "entries"}]
        assert client.read("finance", "entries", columns=["id"], where={"id": 1}, limit=2, offset=3) == [{"id": 1}]
        assert client.insert("finance", "entries", [{"id": 1}, {"id": 2}]) == 2
        assert client.update("finance", "entries", {"id": 2}, {"id": 1}) == 1
        assert client.delete("finance", "entries", {"id": 2}) == 1
    exchanges = [request for request in requests if request["path"].endswith("/access/token")]
    assert [request["body"] for request in exchanges] == [{"package": "finance", "permissions": [permission]} for permission in ("read", "write", "delete")]
    assert all(request["auth"] == "Bearer " + SERVICE for request in exchanges)
    data = [request for request in requests if not request["path"].endswith("/access/token")]
    assert data[0]["method"] == "GET"
    assert data[1]["body"] == {"columns": ["id"], "where": {"id": 1}, "limit": 2, "offset": 3}
    assert all(request["auth"].startswith("Bearer scope-") for request in data)


def test_expiry_margin_forces_exchange(endpoint):
    url, requests, responses = endpoint
    with CorporateClient(url, SERVICE, settings=ClientSettings(refresh_margin_seconds=1)) as client:
        client.read("finance", "entries")
        cached = client._tokens[("finance", "read")]
        cached.expires_at = datetime.now(timezone.utc) + timedelta(milliseconds=100)
        client.read("finance", "entries")
    assert len([r for r in requests if r["path"].endswith("/access/token")]) == 2


def test_unauthorized_data_is_refreshed_once(endpoint):
    url, requests, responses = endpoint
    responses.extend([(401, {"detail": "expired"}), (401, {"detail": "still revoked"})])
    with CorporateClient(url, SERVICE) as client:
        with pytest.raises(CorporateError) as rejected:
            client.insert("finance", "entries", [{"id": 1}])
    assert rejected.value.status_code == 401
    assert len(requests) == 4
    assert [r["path"] for r in requests].count("/api/corporate/data/finance/rows/entries/insert") == 2


@pytest.mark.parametrize("status", [403, 404, 422, 500, 503])
def test_forbidden_or_server_error_never_retries_write(endpoint, status):
    url, requests, responses = endpoint
    responses.append((status, {"detail": "rejected"}))
    with CorporateClient(url, SERVICE) as client:
        with pytest.raises(CorporateError) as rejected:
            client.insert("finance", "entries", [{"id": 1}])
    assert rejected.value.status_code == status
    assert len(requests) == 2


def test_network_disconnect_never_retries_write(endpoint):
    url, requests, responses = endpoint
    responses.append((200, None))
    with CorporateClient(url, SERVICE) as client:
        with pytest.raises(CorporateError) as rejected:
            client.insert("finance", "entries", [{"id": 1}])
    assert rejected.value.status_code is None
    assert "not automatically retried" in str(rejected.value)
    assert len(requests) == 2


def test_errors_redact_account_and_current_scoped_token(endpoint):
    url, requests, responses = endpoint
    responses.append((403, {"detail": SERVICE + " scope-1 must be redacted"}))
    with CorporateClient(url, SERVICE) as client:
        with pytest.raises(CorporateError) as rejected:
            client.read("finance", "entries")
    assert SERVICE not in str(rejected.value) and "scope-1" not in str(rejected.value)


@pytest.mark.parametrize("operation,response", [("tables", {}), ("read", {}), ("read", {"rows": "not rows"}), ("insert", {"affected_rows": -1}), ("insert", {"affected_rows": True})])
def test_malformed_success_response_is_explicit_error(endpoint, operation, response):
    url, requests, responses = endpoint
    responses.append((200, response))
    with CorporateClient(url, SERVICE) as client:
        with pytest.raises(CorporateError):
            if operation == "tables":
                client.tables("finance")
            elif operation == "read":
                client.read("finance", "entries")
            else:
                client.insert("finance", "entries", [{"id": 1}])


def test_invalid_json_response_is_explicit_error(endpoint):
    url, _, responses = endpoint
    responses.append((200, b"not-json"))
    with CorporateClient(url, SERVICE) as client:
        with pytest.raises(CorporateError, match="invalid JSON"):
            client.read("finance", "entries")


@pytest.mark.parametrize("package,table", [("../finance", "entries"), ("finance", "entries;DROP"), ("finance/other", "entries"), ("finance", "../entries")])
def test_identifiers_fail_before_any_request(endpoint, package, table):
    url, requests, _ = endpoint
    with CorporateClient(url, SERVICE) as client:
        with pytest.raises(ValueError):
            client.read(package, table)
    assert requests == []


@pytest.mark.parametrize("values", [{}, {"GREENHOUSE_CORPORATE_API_URL": "http://localhost/api/corporate"}, {"GREENHOUSE_CORPORATE_TOKEN": "secret"}])
def test_missing_managed_env_has_actionable_safe_error(values):
    with pytest.raises(ValueError, match="Share a Corporate package"):
        CorporateClient.from_env(environ=values)


@pytest.mark.parametrize("settings", [{"timeout_seconds": 0}, {"timeout_seconds": float("nan")}, {"timeout_seconds": float("inf")}, {"refresh_margin_seconds": -1}, {"refresh_margin_seconds": float("inf")}])
def test_configuration_bounds(settings):
    with pytest.raises(ValueError):
        ClientSettings(**settings)


@pytest.mark.parametrize("url", ["relative", "file:///tmp/db", "https://user:secret@example.com", "https://example.com?token=secret", "https://example.com#secret"])
def test_invalid_url_cannot_leak_credentials(url):
    with pytest.raises(ValueError) as rejected:
        CorporateClient(url, SERVICE)
    assert "secret" not in str(rejected.value)


@pytest.mark.parametrize("answer", [{}, {"token": "scope"}, {"token": "", "expires_at": "2099-01-01T00:00:00Z"}, {"token": "scope", "expires_at": "2099-01-01T00:00:00"}, {"token": "scope", "expires_at": "2000-01-01T00:00:00Z"}, {"token": "scope", "expires_at": "garbage"}])
def test_malformed_token_response_does_not_attempt_data_request(endpoint, answer):
    url, requests, _ = endpoint
    requests.token_answers.append((200, answer))
    with CorporateClient(url, SERVICE) as client:
        with pytest.raises(CorporateError, match="invalid access token"):
            client.read("finance", "entries")
    assert len(requests) == 1


def test_exchange_denial_never_retries_or_attempts_data(endpoint):
    url, requests, _ = endpoint
    requests.token_answers.append((404, {"detail": "Package not shared"}))
    with CorporateClient(url, SERVICE) as client:
        with pytest.raises(CorporateError) as rejected:
            client.read("unshared", "entries")
    assert rejected.value.status_code == 404 and len(requests) == 1


def test_cache_does_not_cross_package_scope(endpoint):
    url, requests, _ = endpoint
    with CorporateClient(url, SERVICE) as client:
        client.read("finance", "entries")
        client.read("operations", "entries")
        client.read("finance", "entries")
        assert len(client._tokens) == 2
    assert client._tokens == {}
    exchanges = [request["body"] for request in requests if request["path"].endswith("/access/token")]
    assert exchanges == [{"package": "finance", "permissions": ["read"]}, {"package": "operations", "permissions": ["read"]}]


def test_empty_mutation_filters_rejected_without_network(endpoint):
    url, requests, _ = endpoint
    with CorporateClient(url, SERVICE) as client:
        with pytest.raises(ValueError):
            client.update("finance", "entries", {"id": 2}, {})
        with pytest.raises(ValueError):
            client.update("finance", "entries", {}, {"id": 1})
        with pytest.raises(ValueError):
            client.delete("finance", "entries", {})
    assert requests == []


def test_user_session_is_per_operation_and_never_sent_to_exchange(endpoint):
    url, requests, responses = endpoint
    responses.extend([(200, {"affected_rows": 1}), (200, {"affected_rows": 1}), (200, {"affected_rows": 1})])
    with CorporateClient(url, SERVICE) as client:
        client.insert("finance", "entries", [{"id": 1}], user_session="signed-user-a")
        client.update("finance", "entries", {"id": 2}, {"id": 1}, user_session="signed-user-b")
        client.delete("finance", "entries", {"id": 2})
    exchanges = [r for r in requests if r["path"].endswith("/access/token")]
    assert all(r["user_session"] is None for r in exchanges)
    data = [r for r in requests if not r["path"].endswith("/access/token")]
    assert [r["user_session"] for r in data] == ["signed-user-a", "signed-user-b", None]


def test_user_session_read_and_tables(endpoint):
    url, requests, responses = endpoint
    responses.extend([(200, []), (200, {"rows": []})])
    with CorporateClient(url, SERVICE) as client:
        assert client.tables("finance", user_session="signed-user") == []
        assert client.read("finance", "entries", user_session="signed-user") == []
    assert [r["user_session"] for r in requests] == [None, "signed-user", "signed-user"]


def test_user_session_redacted_from_errors_and_preserved_on_auth_retry(endpoint):
    url, requests, responses = endpoint
    responses.extend([(401, {"detail": "expired signed-user"}), (401, {"detail": "invalid signed-user"})])
    with CorporateClient(url, SERVICE) as client:
        with pytest.raises(CorporateError) as rejected:
            client.insert("finance", "entries", [{"id": 1}], user_session="signed-user")
    assert "signed-user" not in str(rejected.value)
    data = [r for r in requests if not r["path"].endswith("/access/token")]
    assert [r["user_session"] for r in data] == ["signed-user", "signed-user"]


@pytest.mark.parametrize("session", ["", " ", "abc\n", "abc\r", 123])
def test_invalid_user_session_rejected_before_network(endpoint, session):
    url, requests, responses = endpoint
    with CorporateClient(url, SERVICE) as client:
        with pytest.raises(ValueError):
            client.read("finance", "entries", user_session=session)
    assert requests == []
