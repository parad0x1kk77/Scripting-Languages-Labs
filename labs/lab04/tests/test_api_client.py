from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ID = "CVE-2099-10001"


def make_response(status_code: int = 200, payload=None) -> Mock:
    """Створює фейкову відповідь сервера."""
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload
    return response


def test_headers_without_key():
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_headers_with_fake_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  fake-test-key  ")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-test-key",
    }


@pytest.mark.parametrize("value", ["", "   "])
def test_headers_empty_key_ignored(monkeypatch, value):
    monkeypatch.setenv("NVD_API_KEY", value)
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_fetch_uses_expected_request(monkeypatch):
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = make_response(200, payload)
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    assert api_client.fetch_response(CVE_ID) == payload
    fake_get.assert_called_once_with(
        URL,
        params={"cveId": CVE_ID},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_sends_key_in_header_not_url(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "fake-test-key")
    fake_get = Mock(return_value=make_response(200, {"vulnerabilities": []}))
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    api_client.fetch_response(CVE_ID)
    kwargs = fake_get.call_args.kwargs
    assert kwargs["headers"]["apiKey"] == "fake-test-key"
    assert kwargs["params"] == {"cveId": CVE_ID}
    assert "fake-test-key" not in fake_get.call_args.args[0]


@pytest.mark.parametrize("status", [404, 500, 503])
def test_fetch_http_error(monkeypatch, status):
    response = make_response(status)
    response.raise_for_status.side_effect = requests.HTTPError(
        f"{status} Error", response=response
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.HTTPError) as exc_info:
        api_client.fetch_response(CVE_ID)
    assert exc_info.value.response.status_code == status
    response.json.assert_not_called()


@pytest.mark.parametrize("status", [204, 301, 302])
def test_fetch_unexpected_status(monkeypatch, status):
    response = make_response(status)
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(api_client.UnexpectedStatusError):
        api_client.fetch_response(CVE_ID)
    response.json.assert_not_called()


@pytest.mark.parametrize(
    "exception", [requests.ConnectionError, requests.Timeout, requests.ReadTimeout]
)
def test_fetch_network_error(monkeypatch, exception):
    monkeypatch.setattr(api_client.requests, "get", Mock(side_effect=exception()))
    with pytest.raises(exception):
        api_client.fetch_response(CVE_ID)


def test_fetch_invalid_json(monkeypatch):
    response = make_response(200)
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response(CVE_ID)


def test_real_network_is_blocked():
    with pytest.raises(AttributeError):
        requests.get(URL, timeout=(3.05, 10))
