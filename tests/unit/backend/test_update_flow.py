"""Check de versión y descarga del autoupdate, con ``requests.get`` sustituido (sin red)."""

from __future__ import annotations

import os

import pytest
import requests

from bifrost_backend.common import updates

CURRENT = "2.0.0"


class FakeResponse:
    def __init__(self, status: int = 200, json_data: dict | None = None, content: bytes = b""):
        self.status_code = status
        self._json = json_data if json_data is not None else {}
        self.content = content

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self) -> dict:
        return self._json


@pytest.fixture
def fake_get(monkeypatch):
    """Sustituye requests.get. Devuelve ``set(response=..., error=...)`` y la lista de URLs pedidas."""
    monkeypatch.setattr(updates, "__version__", CURRENT)
    state: dict = {"response": FakeResponse(), "error": None}
    urls: list[str] = []

    def _get(url, **kwargs):
        urls.append(url)
        if state["error"] is not None:
            raise state["error"]
        return state["response"]

    monkeypatch.setattr(updates.requests, "get", _get)

    def _set(response: FakeResponse | None = None, error: Exception | None = None):
        if response is not None:
            state["response"] = response
        state["error"] = error

    _set.urls = urls
    return _set


@pytest.mark.parametrize("tag, expected", [
    ("v2.0.1", "v2.0.1"),       # más nueva
    ("v2.10.0", "v2.10.0"),     # 10 > 0 numéricamente
    ("v2.0.0", None),           # igual
    ("v1.9.9", None),           # más antigua
])
def test_check_update_version(fake_get, tag, expected):
    fake_get(FakeResponse(json_data={"tag_name": tag}))
    assert updates.check_update_version() == expected


def test_check_asks_github_releases_api(fake_get):
    fake_get(FakeResponse(json_data={"tag_name": "v9.9.9"}))
    updates.check_update_version()
    assert fake_get.urls == [f"https://api.github.com/repos/{updates.REPO}/releases/latest"]


def test_check_returns_none_when_api_fails(fake_get):
    fake_get(FakeResponse(status=500))
    assert updates.check_update_version() is None


def test_check_returns_none_when_tag_missing(fake_get):
    fake_get(FakeResponse(json_data={}))
    assert updates.check_update_version() is None


def test_check_returns_none_when_there_is_no_network(fake_get):
    fake_get(error=requests.ConnectionError("sin red"))
    assert updates.check_update_version() is None


def test_download_new_binary(fake_get):
    payload = b"MZ-fake-installer" * 1000
    fake_get(FakeResponse(content=payload))
    path = updates.download_new_binary("bifrost-test")
    try:
        with open(path, "rb") as f:
            assert f.read() == payload
    finally:
        os.remove(path)
    expected = f"https://github.com/{updates.REPO}/releases/latest/download/bifrost-test{updates.get_update_file_suffix()}"
    assert fake_get.urls == [expected]


def test_download_missing_asset_raises(fake_get):
    fake_get(FakeResponse(status=404))
    with pytest.raises(requests.HTTPError):
        updates.download_new_binary("bifrost-test")
