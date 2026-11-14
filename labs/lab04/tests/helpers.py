from typing import Any

CVE_ID = "CVE-2099-10001"


def make_payload(
    score: Any = 9.8,
    field_value: Any = "LOW",
    status: Any = "Analyzed",
) -> dict[str, Any]:
    """Створює тестову відповідь NVD з одним записом."""
    cvss_data: dict[str, Any] = {
        "version": "3.1",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "baseScore": score,
        "attackComplexity": field_value,
    }
    cve: dict[str, Any] = {
        "id": CVE_ID,
        "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": "Test vulnerability."}],
        "metrics": {
            "cvssMetricV31": [
                {"source": "nvd@nist.gov", "type": "Primary", "cvssData": cvss_data}
            ]
        },
    }
    return {"vulnerabilities": [{"cve": cve}]}