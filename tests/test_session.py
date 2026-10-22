import httpx
import respx

from frappectl import session_login
from frappectl.session import ClientFactory

BASE = "http://localhost"


@respx.mock
def test_password_profile_client_sends_sid_cookie(fake_config):
    fake_config.add_password_profile("acme", BASE, "alice", "secret", sid="CACHED")
    route = respx.get(f"{BASE}/api/v2/document/ToDo/X/").mock(
        return_value=httpx.Response(200, json={"data": {"name": "X"}})
    )
    client = ClientFactory().create("acme", interactive=False, debug=False)
    client.get_document("ToDo", "X")
    assert "sid=CACHED" in route.calls.last.request.headers.get("cookie", "")


@respx.mock
def test_password_profile_relogins_on_401_and_persists(fake_config, monkeypatch):
    fake_config.add_password_profile("acme", BASE, "alice", "secret", sid="STALE")
    monkeypatch.setattr(session_login, "login", lambda site, user, pwd: "FRESH")
    route = respx.get(f"{BASE}/api/v2/document/ToDo/X/")
    route.side_effect = [
        httpx.Response(401, json={"errors": [{"message": "auth"}]}),
        httpx.Response(200, json={"data": {"name": "X"}}),
    ]
    client = ClientFactory().create("acme", interactive=False, debug=False)
    assert client.get_document("ToDo", "X") == {"name": "X"}
    assert "sid=FRESH" in route.calls[-1].request.headers.get("cookie", "")
    assert fake_config.password_sid("acme") == "FRESH"


@respx.mock
def test_password_profile_keeps_sid_across_same_site_redirect(fake_config):
    # Sites behind nginx 301 the trailing-slash v2 paths; httpx rebuilds the
    # redirected request's Cookie header from the client cookie jar only.
    site = "https://acme.example.com"
    fake_config.add_password_profile("acme", site, "alice", "secret", sid="CACHED")
    respx.get(f"{site}/api/v2/document/ToDo/X/").mock(
        return_value=httpx.Response(
            301, headers={"Location": f"{site}/api/v2/document/ToDo/X"}
        )
    )
    target = respx.get(f"{site}/api/v2/document/ToDo/X").mock(
        return_value=httpx.Response(200, json={"data": {"name": "X"}})
    )
    client = ClientFactory().create("acme", interactive=False, debug=False)
    assert client.get_document("ToDo", "X") == {"name": "X"}
    assert "sid=CACHED" in target.calls.last.request.headers.get("cookie", "")


@respx.mock
def test_password_profile_does_not_send_sid_to_another_host(fake_config):
    site = "https://acme.example.com"
    fake_config.add_password_profile("acme", site, "alice", "secret", sid="CACHED")
    respx.get(f"{site}/api/v2/document/ToDo/X/").mock(
        return_value=httpx.Response(
            302, headers={"Location": "https://evil.example.org/collect"}
        )
    )
    other = respx.get("https://evil.example.org/collect").mock(
        return_value=httpx.Response(200, json={"data": {}})
    )
    client = ClientFactory().create("acme", interactive=False, debug=False)
    client.get_document("ToDo", "X")
    assert "sid" not in other.calls.last.request.headers.get("cookie", "")


@respx.mock
def test_password_profile_does_not_send_sid_over_plain_http(fake_config):
    site = "https://acme.example.com"
    fake_config.add_password_profile("acme", site, "alice", "secret", sid="CACHED")
    respx.get(f"{site}/api/v2/document/ToDo/X/").mock(
        return_value=httpx.Response(
            301, headers={"Location": "http://acme.example.com/api/v2/document/ToDo/X"}
        )
    )
    downgraded = respx.get("http://acme.example.com/api/v2/document/ToDo/X").mock(
        return_value=httpx.Response(200, json={"data": {}})
    )
    client = ClientFactory().create("acme", interactive=False, debug=False)
    client.get_document("ToDo", "X")
    assert "sid" not in downgraded.calls.last.request.headers.get("cookie", "")
