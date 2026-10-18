# Лабораторна робота №3
## Файли

main.py: FastAPI-застосунок, маршрути /ping та /student
database.py: підключення до SQLite і створення таблиць
schema.sql: готова схема таблиць categories і records
repository.py: параметризовані SQL-запити
schemas.py: Pydantic-моделі запитів і відповідей
seed.py: початкове заповнення бази з data/seed.json
routers/categories.py: маршрути категорій
routers/records.py: маршрути записів
data/seed.json: навчальні дані (3 категорії, 8 записів)
data/lab3.sqlite3: база даних, створюється програмою

## Запуск

Команди виконуються з кореня репозиторію.

Встановлення залежностей:

```
pip install -r requirements.txt
```

Створення бази та початкове заповнення:

```
python -m labs.lab03.database
python -m labs.lab03.seed
```

Запуск API:

```
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

Swagger UI: http://127.0.0.1:8000/docs

## Перевірка стилю

```
ruff check labs/lab03
ruff format --check labs/lab03
```
