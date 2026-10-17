import json
import sqlite3
from pathlib import Path
from contextlib import closing
from .database import get_connection

BASE_DIR = Path(__file__).resolve().parent
SEED_PATH = BASE_DIR / "data" / "seed.json"

def seed_data() -> None:
    with open(SEED_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    try:
        with closing(get_connection()) as connection:
            with connection:
                cursor = connection.execute("SELECT COUNT(*) FROM categories")
                if cursor.fetchone()[0] > 0:
                    print("База даних вже містить дані. Повторне заповнення скасовано.")
                    return

                for cat in data["categories"]:
                    connection.execute(
                        "INSERT INTO categories (id, name) VALUES (?, ?)",
                        (cat["id"], cat["name"])
                    )

                for rec in data["records"]:
                    connection.execute(
                        "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
                        (rec["code"], rec["title"], rec["category_id"], rec["value"], rec["status"])
                    )

                print("Успішно додано 3 категорії та 8 записів!")

    except sqlite3.IntegrityError as e:
        print(f"Помилка обмежень даних. Пакет змін скасовано: {e}")
    except Exception as e:
        print(f"Неочікувана помилка: {e}")

if __name__ == "__main__":
    seed_data()