import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def cve_id_type(value: str) -> str:
    """Перевіряє формат ідентифікатора CVE."""
    if CVE_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            f"некоректний ідентифікатор CVE: {value!r} (приклад: CVE-2021-44228)"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    """Створює парсер аргументів."""
    parser = argparse.ArgumentParser(
        description="Перегляд запису CVE з NVD і аналіз за правилом варіанта."
    )
    parser.add_argument(
        "--cve", required=True, type=cve_id_type, help="ідентифікатор CVE"
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="шлях до локальної відповіді NVD (JSON, UTF-8); без мережі",
    )
    return parser


def is_valid_variant(value: Any) -> bool:
    """Перевіряє, що номер варіанта від 1 до 15."""
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 15


def load_response(path: Path) -> Any:
    """Читає відповідь NVD з JSON-файла."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def error(message: str) -> None:
    """Виводить помилку в stderr."""
    print(f"Помилка: {message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    """Запускає програму і повертає код завершення."""
    args = build_parser().parse_args(argv)

    if not is_valid_variant(VARIANT_NUMBER):
        error(f"VARIANT_NUMBER має бути цілим числом від 1 до 15: {VARIANT_NUMBER!r}")
        return 2

    if args.input is not None:
        try:
            payload = load_response(args.input)
        except OSError as exc:
            error(f"не вдалося прочитати файл {args.input}: {exc.strerror}")
            return 1
        except UnicodeDecodeError:
            error(f"файл {args.input} не є текстом у кодуванні UTF-8")
            return 1
        except json.JSONDecodeError as exc:
            error(f"файл {args.input} містить некоректний JSON (рядок {exc.lineno})")
            return 1
    else:
        try:
            payload = api_client.fetch_response(args.cve)
        except requests.Timeout:
            error("перевищено час очікування відповіді NVD")
            return 1
        except requests.ConnectionError:
            error("не вдалося з'єднатися з NVD")
            return 1
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "?"
            error(f"NVD повернув HTTP-помилку, статус {status}")
            return 1
        except api_client.UnexpectedStatusError as exc:
            error(f"NVD повернув неочікуваний статус {exc.status_code}")
            return 1
        except requests.exceptions.JSONDecodeError:
            error("відповідь NVD не є коректним JSON")
            return 1
        except requests.RequestException:
            error("запит до NVD не вдалося виконати")
            return 1

    try:
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except ValueError as exc:
        error(f"некоректні дані відповіді NVD: {exc}")
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=4))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())