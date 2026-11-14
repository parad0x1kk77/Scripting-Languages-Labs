import copy
from typing import Any

import pytest

from labs.lab04 import analysis
from labs.lab04.tests.helpers import CVE_ID, make_payload

VARIANT = 2


def analyze(payload: Any, variant: int = VARIANT) -> dict[str, Any]:
    """Перевіряє відповідь і будує звіт."""
    record = analysis.extract_record(payload, CVE_ID)
    return analysis.build_report(record, CVE_ID, variant)


def metric(source: str, metric_type: str, score: float, complexity: str) -> dict:
    """Створює одну оцінку для cvssMetricV31."""
    return {
        "source": source,
        "type": metric_type,
        "cvssData": {
            "version": "3.1",
            "baseScore": score,
            "attackComplexity": complexity,
        },
    }


@pytest.mark.parametrize(
    "score, complexity, expected",
    [
        (7.9, "LOW", "other"),
        (8.0, "LOW", "review"),
        (8.1, "LOW", "review"),
        (10, "LOW", "review"),
        (9.8, "HIGH", "other"),
        (0.0, "LOW", "other"),
    ],
)
def test_threshold_and_field(score, complexity, expected):
    report = analyze(make_payload(score=score, field_value=complexity))
    assert report["decision"] == expected
    assert report["score"] == score
    assert report["observed"] == complexity


def test_sample_full_report(sample_payload):
    report = analyze(sample_payload)
    assert report == {
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


@pytest.mark.parametrize(
    "variant, expected",
    [(v, "review") for v in range(1, 8)] + [(v, "other") for v in range(8, 16)],
)
def test_sample_for_all_variants(sample_payload, variant, expected):
    assert analyze(sample_payload, variant)["decision"] == expected


def test_not_found():
    payload = {"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
    assert analysis.extract_record(payload, CVE_ID) is None
    report = analyze(payload)
    assert report["decision"] == "not_found"
    assert report["cve_id"] == CVE_ID
    assert report["variant"] == VARIANT
    assert report["rule"] == {
        "threshold": 8.0,
        "field": "attackComplexity",
        "expected": "LOW",
    }
    for key in (
        "description",
        "vuln_status",
        "cvss_version",
        "score",
        "score_source",
        "vector",
        "observed",
    ):
        assert report[key] is None


def test_rejected_ignores_high_score():
    report = analyze(make_payload(score=10.0, status="Rejected"))
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Test vulnerability."
    assert report["score"] is None
    assert report["observed"] is None


def test_rejected_does_not_validate_scores():
    payload = make_payload(score="bad", status="Rejected")
    assert analyze(payload)["decision"] == "rejected"


def test_missing_status_is_insufficient_data():
    payload = make_payload()
    del payload["vulnerabilities"][0]["cve"]["vulnStatus"]
    report = analyze(payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["description"] == "Test vulnerability."
    assert report["score"] is None


def _without_metrics(payload):
    del payload["vulnerabilities"][0]["cve"]["metrics"]


def _without_v31(payload):
    del payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"]


def _empty_v31(payload):
    payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = []


@pytest.mark.parametrize("mutate", [_without_metrics, _without_v31, _empty_v31])
def test_missing_score_is_insufficient_data(mutate):
    payload = make_payload()
    mutate(payload)
    report = analyze(payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] == "Analyzed"
    assert report["score"] is None


def test_missing_variant_field_is_insufficient_data():
    payload = make_payload(score=9.8)
    cvss_data = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    del cvss_data["cvssData"]["attackComplexity"]
    report = analyze(payload)
    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


@pytest.mark.parametrize("bad_value", [None, "MEDIUM", "low", 1, True])
def test_invalid_variant_field_raises(bad_value):
    with pytest.raises(ValueError):
        analyze(make_payload(field_value=bad_value))


@pytest.mark.parametrize(
    "bad_score", ["9.8", True, None, float("nan"), float("inf"), -0.1, 10.1]
)
def test_invalid_base_score_raises(bad_score):
    with pytest.raises(ValueError):
        analyze(make_payload(score=bad_score))


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": [{"cve": {"id": CVE_ID}}, {"cve": {"id": CVE_ID}}]},
        {"vulnerabilities": [{"cve": "text"}]},
        {"vulnerabilities": [{"cve": {"id": "CVE-2099-99999"}}]},
    ],
)
def test_invalid_payload_structure_raises(payload):
    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


def _metrics_null(payload):
    payload["vulnerabilities"][0]["cve"]["metrics"] = None


def _v31_not_list(payload):
    payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = {}


def _v31_item_not_dict(payload):
    payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = ["x"]


def _version_not_31(payload):
    cve = payload["vulnerabilities"][0]["cve"]
    cve["metrics"]["cvssMetricV31"][0]["cvssData"]["version"] = "3.0"


def _empty_status(payload):
    payload["vulnerabilities"][0]["cve"]["vulnStatus"] = ""


def _descriptions_not_list(payload):
    payload["vulnerabilities"][0]["cve"]["descriptions"] = "text"


@pytest.mark.parametrize(
    "mutate",
    [
        _metrics_null,
        _v31_not_list,
        _v31_item_not_dict,
        _version_not_31,
        _empty_status,
        _descriptions_not_list,
    ],
)
def test_invalid_present_fields_raise(mutate):
    payload = make_payload()
    mutate(payload)
    with pytest.raises(ValueError):
        analyze(payload)


@pytest.mark.parametrize("variant", [0, 16, True, "2", 2.0])
def test_build_report_rejects_invalid_variant(variant):
    with pytest.raises(ValueError):
        analysis.build_report(None, CVE_ID, variant)


def _with_metrics(metrics: list[dict]) -> dict:
    payload = make_payload()
    payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = metrics
    return payload


def test_primary_has_priority_over_earlier_secondary():
    payload = _with_metrics(
        [
            metric("secondary@example.invalid", "Secondary", 9.9, "HIGH"),
            metric("nvd@nist.gov", "Primary", 8.5, "LOW"),
        ]
    )
    report = analyze(payload)
    assert report["score_source"] == "nvd@nist.gov"
    assert report["score"] == 8.5
    assert report["decision"] == "review"


def test_first_metric_selected_without_primary():
    payload = _with_metrics(
        [
            metric("first@example.invalid", "Secondary", 7.5, "LOW"),
            metric("second@example.invalid", "Secondary", 9.9, "LOW"),
        ]
    )
    report = analyze(payload)
    assert report["score_source"] == "first@example.invalid"
    assert report["score"] == 7.5
    assert report["decision"] == "other"


def test_score_and_field_taken_from_same_metric():
    payload = _with_metrics(
        [
            metric("secondary@example.invalid", "Secondary", 9.9, "LOW"),
            metric("nvd@nist.gov", "Primary", 9.0, "HIGH"),
        ]
    )
    report = analyze(payload)
    assert report["observed"] == "HIGH"
    assert report["decision"] == "other"


def test_first_non_empty_english_description():
    payload = make_payload()
    payload["vulnerabilities"][0]["cve"]["descriptions"] = [
        {"lang": "es", "value": "Descripción"},
        {"lang": "en", "value": "   "},
        {"lang": "en", "value": "English text."},
    ]
    assert analyze(payload)["description"] == "English text."


def test_optional_report_fields_missing_are_null():
    payload = make_payload()
    selected = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    del selected["source"]
    del selected["cvssData"]["version"]
    del selected["cvssData"]["vectorString"]
    report = analyze(payload)
    assert report["score_source"] is None
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["decision"] == "review"


def test_payload_is_not_modified(sample_payload):
    original = copy.deepcopy(sample_payload)
    analyze(sample_payload)
    assert sample_payload == original