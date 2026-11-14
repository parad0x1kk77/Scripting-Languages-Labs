import math
from typing import Any


class NVDDataError(ValueError):
    """Помилка в даних відповіді NVD."""


ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "attackVector": frozenset({"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}),
    "attackComplexity": frozenset({"LOW", "HIGH"}),
    "privilegesRequired": frozenset({"NONE", "LOW", "HIGH"}),
    "userInteraction": frozenset({"NONE", "REQUIRED"}),
    "scope": frozenset({"UNCHANGED", "CHANGED"}),
    "confidentialityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "integrityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "availabilityImpact": frozenset({"NONE", "LOW", "HIGH"}),
}

RULES: dict[int, dict[str, Any]] = {
    1: {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
    2: {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
    3: {"threshold": 7.0, "field": "privilegesRequired", "expected": "NONE"},
    4: {"threshold": 8.0, "field": "userInteraction", "expected": "NONE"},
    5: {"threshold": 7.0, "field": "confidentialityImpact", "expected": "HIGH"},
    6: {"threshold": 7.0, "field": "integrityImpact", "expected": "HIGH"},
    7: {"threshold": 7.0, "field": "availabilityImpact", "expected": "HIGH"},
    8: {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
    9: {"threshold": 5.0, "field": "attackVector", "expected": "LOCAL"},
    10: {"threshold": 6.0, "field": "privilegesRequired", "expected": "LOW"},
    11: {"threshold": 6.0, "field": "userInteraction", "expected": "REQUIRED"},
    12: {"threshold": 6.0, "field": "confidentialityImpact", "expected": "LOW"},
    13: {"threshold": 6.0, "field": "integrityImpact", "expected": "LOW"},
    14: {"threshold": 6.0, "field": "availabilityImpact", "expected": "LOW"},
    15: {"threshold": 8.0, "field": "attackComplexity", "expected": "HIGH"},
}


def _optional_string(container: dict[str, Any], key: str, where: str) -> str | None:
    """Повертає рядок або None, якщо поля немає."""
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, str) or not value.strip():
        raise NVDDataError(f"{where}.{key} має бути непорожнім рядком")
    return value


def _english_description(cve: dict[str, Any]) -> str | None:
    """Шукає перший непорожній англійський опис."""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        raise NVDDataError("cve.descriptions має бути списком")
    result = None
    for item in descriptions:
        if not isinstance(item, dict):
            raise NVDDataError("елементи cve.descriptions мають бути об'єктами")
        lang, value = item.get("lang"), item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            raise NVDDataError("lang і value в cve.descriptions мають бути рядками")
        if result is None and lang == "en" and value.strip():
            result = value
    return result


def _is_valid_score(score: Any) -> bool:
    """Перевіряє, що оцінка є числом від 0 до 10."""
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return False
    return math.isfinite(score) and 0 <= score <= 10


def _extract_cvss(cve: dict[str, Any]) -> dict[str, Any] | None:
    """Вибирає оцінку CVSS v3.1 або повертає None."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise NVDDataError("cve.metrics має бути об'єктом")
    if "cvssMetricV31" not in metrics:
        return None
    metric_list = metrics["cvssMetricV31"]
    if not isinstance(metric_list, list):
        raise NVDDataError("metrics.cvssMetricV31 має бути списком")
    if not metric_list:
        return None
    if not all(isinstance(item, dict) for item in metric_list):
        raise NVDDataError("елементи cvssMetricV31 мають бути об'єктами")

    selected = next(
        (item for item in metric_list if item.get("type") == "Primary"),
        metric_list[0],
    )

    cvss_data = selected.get("cvssData")
    if not isinstance(cvss_data, dict):
        raise NVDDataError("cvssData має бути об'єктом")
    score = cvss_data.get("baseScore")
    if not _is_valid_score(score):
        raise NVDDataError("baseScore має бути скінченним числом від 0 до 10")

    version = _optional_string(cvss_data, "version", "cvssData")
    if version is not None and version != "3.1":
        raise NVDDataError("cvssData.version має дорівнювати '3.1'")

    return {
        "version": version,
        "score": score,
        "source": _optional_string(selected, "source", "cvssMetricV31"),
        "vector": _optional_string(cvss_data, "vectorString", "cvssData"),
        "data": dict(cvss_data),
    }


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Перевіряє відповідь NVD і повертає запис або None, якщо CVE не знайдено.

    Формат запису:
        vuln_status - статус NVD або None
        description - англійський опис або None
        cvss - None (немає оцінки, Rejected або немає статусу) або словник
               з ключами version, score, source, vector і data (копія cvssData)
    """
    if not isinstance(payload, dict):
        raise NVDDataError("відповідь має бути JSON-об'єктом")
    if "vulnerabilities" not in payload:
        raise NVDDataError("у відповіді немає поля vulnerabilities")
    vulnerabilities = payload["vulnerabilities"]
    if not isinstance(vulnerabilities, list):
        raise NVDDataError("vulnerabilities має бути списком")
    if len(vulnerabilities) > 1:
        raise NVDDataError("для одного CVE очікується не більше одного запису")
    if not vulnerabilities:
        return None

    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise NVDDataError("елемент vulnerabilities має містити об'єкт cve")
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise NVDDataError("cve.id не збігається із запитаним ідентифікатором")

    status = _optional_string(cve, "vulnStatus", "cve")
    description = _english_description(cve)

    if status is None or status == "Rejected":
        cvss = None
    else:
        cvss = _extract_cvss(cve)

    return {"vuln_status": status, "description": description, "cvss": cvss}


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Застосовує правило варіанта і формує звіт."""
    if (
        not isinstance(variant, int)
        or isinstance(variant, bool)
        or variant not in RULES
    ):
        raise ValueError(f"невідомий номер варіанта: {variant!r}")
    rule = dict(RULES[variant])
    field = rule["field"]

    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": rule,
        "observed": None,
        "decision": None,
    }

    if record is None:
        report["decision"] = "not_found"
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]

    if record["vuln_status"] == "Rejected":
        report["decision"] = "rejected"
        return report

    cvss = record["cvss"]
    if record["vuln_status"] is None or cvss is None:
        report["decision"] = "insufficient_data"
        return report

    report["cvss_version"] = cvss["version"]
    report["score"] = cvss["score"]
    report["score_source"] = cvss["source"]
    report["vector"] = cvss["vector"]

    if field not in cvss["data"]:
        report["decision"] = "insufficient_data"
        return report

    observed = cvss["data"][field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise NVDDataError(f"недопустиме значення cvssData.{field}: {observed!r}")
    report["observed"] = observed

    if cvss["score"] >= rule["threshold"] and observed == rule["expected"]:
        report["decision"] = "review"
    else:
        report["decision"] = "other"
    return report
