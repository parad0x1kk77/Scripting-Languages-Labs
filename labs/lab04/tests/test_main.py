import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import main
from labs.lab04.tests.helpers import CVE_ID, make_payload

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "nvd_sample.json"

EXPECTED_SAMPLE_REPORT = {
    "cve_id": "CVE-2099-10001",
    "variant": 2,
    "description": "Synthetic vulnerability for offline API testing.",
    "vuln_status": "Analyzed",
    "cvss_version": "3.1",
    "score": 9.8,
    "score_source": "nvd@nist.gov",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "rule": {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
    "observed": "LOW",
    "decision": "review",
}


@pytest.fixture
def no_fetch(monkeypatch) -> Mock:
    """Підміняє клієнт, щоб перевірити, що мережа не використовується."""
    fake = Mock(side_effect=AssertionError("мережевий запит не очікувався"))
    monkeypatch.setattr(main.api_client, "fetch_response", fake)
    return fake


def test_local_sample_report(capsys, no_fetch):
    code = main.main(["--cve", CVE_ID, "--input", str(SAMPLE)])
    out, err = capsys.readouterr()
    assert code == 0
    assert json.loads(out) == EXPECTED_SAMPLE_REPORT
    assert err == ""
    no_fetch.assert_not_called()


def test_local_output_keeps_non_ascii(tmp_path, capsys, no_fetch):
    payload = make_payload()
    payload["vulnerabilities"][0]["cve"]["descriptions"] = [
        {"lang": "en", "value": "Опис уразливості"}
    ]
    path = tmp_path / "nvd.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    assert main.main(["--cve", CVE_ID, "--input", str(path)]) == 0
    out, _ = capsys.readouterr()
    assert "Опис уразливості" in out


def test_local_not_found_exit_zero(tmp_path, capsys, no_fetch):
    path = tmp_path / "empty.json"
    path.write_text('{"vulnerabilities": []}', encoding="utf-8")

    assert main.main(["--cve", CVE_ID, "--input", str(path)]) == 0
    out, _ = capsys.readouterr()
    assert json.loads(out)["decision"] == "not_found"


def test_missing_file(tmp_path, capsys, no_fetch):
    code = main.main(["--cve", CVE_ID, "--input", str(tmp_path / "missing.json")])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert "не вдалося прочитати файл" in err
    assert "Traceback" not in err


def test_invalid_json_file(tmp_path, capsys, no_fetch):
    path = tmp_path / "broken.json"
    path.write_text('{"vulnerabilities": [', encoding="utf-8")

    code = main.main(["--cve", CVE_ID, "--input", str(path)])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert "некоректний JSON" in err


def test_invalid_data_structure(tmp_path, capsys, no_fetch):
    path = tmp_path / "other_id.json"
    payload = make_payload()
    payload["vulnerabilities"][0]["cve"]["id"] = "CVE-2099-99999"
    path.write_text(json.dumps(payload), encoding="utf-8")

    code = main.main(["--cve", CVE_ID, "--input", str(path)])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert "некоректні дані" in err


@pytest.mark.parametrize(
    "cve",
    ["cve-2021-44228", "CVE-21-44228", "CVE-2021-123", "CVE-2021-44228 ", "abc"],
)
def test_invalid_cve_argument(cve, capsys, no_fetch):
    with pytest.raises(SystemExit) as exc_info:
        main.main(["--cve", cve])
    assert exc_info.value.code == 2
    assert "некоректний ідентифікатор CVE" in capsys.readouterr().err


def test_missing_cve_argument(no_fetch):
    with pytest.raises(SystemExit) as exc_info:
        main.main(["--input", str(SAMPLE)])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("variant", [0, 16, True, "2", None])
def test_invalid_variant_number(monkeypatch, capsys, no_fetch, variant):
    monkeypatch.setattr(main, "VARIANT_NUMBER", variant)
    code = main.main(["--cve", CVE_ID, "--input", str(SAMPLE)])
    out, err = capsys.readouterr()
    assert code == 2
    assert out == ""
    assert "VARIANT_NUMBER" in err


def test_network_mode_calls_client(monkeypatch, capsys):
    fake = Mock(return_value=make_payload(score=7.9))
    monkeypatch.setattr(main.api_client, "fetch_response", fake)

    assert main.main(["--cve", CVE_ID]) == 0
    fake.assert_called_once_with(CVE_ID)
    assert json.loads(capsys.readouterr().out)["decision"] == "other"


def _http_error(status: int) -> requests.HTTPError:
    response = Mock(spec=requests.Response)
    response.status_code = status
    return requests.HTTPError(f"{status} Error", response=response)


@pytest.mark.parametrize(
    "exception, message",
    [
        (requests.ConnectionError("details"), "не вдалося з'єднатися"),
        (requests.ConnectTimeout("details"), "час очікування"),
        (requests.ReadTimeout("details"), "час очікування"),
        (_http_error(404), "статус 404"),
        (_http_error(503), "статус 503"),
        (
            requests.exceptions.JSONDecodeError("Invalid JSON", "{", 1),
            "не є коректним JSON",
        ),
    ],
)
def test_network_errors(monkeypatch, capsys, exception, message):
    monkeypatch.setenv("NVD_API_KEY", "secret-test-key")
    monkeypatch.setattr(main.api_client, "fetch_response", Mock(side_effect=exception))

    code = main.main(["--cve", CVE_ID])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert message in err
    assert "secret-test-key" not in err
    assert "details" not in err
    assert "Traceback" not in err


def test_unexpected_status(monkeypatch, capsys):
    error = main.api_client.UnexpectedStatusError(301)
    monkeypatch.setattr(main.api_client, "fetch_response", Mock(side_effect=error))

    assert main.main(["--cve", CVE_ID]) == 1
    assert "неочікуваний статус 301" in capsys.readouterr().err