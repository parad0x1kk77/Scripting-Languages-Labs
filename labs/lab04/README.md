# Лабораторна робота №4
# Варіант 2

## Встановлення

```
pip install -r requirements.txt
```

## Запуск

Команди виконуються з кореня репозиторію.

```
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json

python -m labs.lab04.main --cve CVE-2021-44228
```

Перша команда працює з локальним файлом, друга робить запит до NVD.
Ключ API необов'язковий. Змінна середовища `NVD_API_KEY`

## Формат звіту

JSON у stdout з полями `cve_id`, `variant`, `description`, `vuln_status`, `cvss_version`,
`score`, `score_source`, `vector`, `rule`, `observed`, `decision`.

`decision`: `not_found`, `rejected`, `insufficient_data`, `review`, `other`.

## Перевірка

```
python -m pytest labs/lab04/tests -q

ruff check labs/lab04

ruff format --check labs/lab04
```