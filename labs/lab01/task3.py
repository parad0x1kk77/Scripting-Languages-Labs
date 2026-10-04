import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

print(f"Студент: {STUDENT_NAME}\nГрупа: {GROUP_NAME}\nВаріант: {VARIANT_NUMBER}")
print()

# Пункт 2
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)


# Клас винятку, який успадковується від exception
class ValidationError(Exception):
    pass


MIN_PASSWORD_LENGTH = 10


# Пункт 1
def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль надто короткий. Мінімальна довжина: {MIN_PASSWORD_LENGTH} символів"
        )

    data_to_hash = password + salt
    hash_object = hashlib.sha3_224(data_to_hash.encode("utf-8"))
    return hash_object.hexdigest()


# Пункт 3
users_to_register = (
    ("admin", "adminadmin123"),
    ("moderator", "ModeratorPassword"),
    ("user01", "User01Password"),
    ("user02", "User02Password"),
    ("user03", "User03Password"),
    ("user04", "User04Password"),
    ("user05", "User05Password"),
    ("user06", "User06Password"),
    ("user07", "User07Password"),
    ("user08", "User08Password"),
)


def create_user(username, password):
    """кортеж (логін, хеш_пароля)"""
    hash_value = generate_hash(password, PERSONAL_SALT)
    return (username, hash_value)


def create_users(users_list):
    """Обробка списку користувачів і збереження у csv"""
    base_dir = os.path.dirname(__file__)
    data_dir = os.path.join(base_dir, "data")
    file_path = os.path.join(data_dir, "users.csv")
    os.makedirs(data_dir, exist_ok=True)

    try:
        with open(file_path, "w", encoding="utf-8") as file:
            for username, password in users_list:
                user_data = create_user(username, password)
                file.write(
                    f"{user_data[0]},{user_data[1]}\n"
                )  # Запис у форматі логін,хеш_пароля
        print("Базу даних успішно створено.")
        print(f"Шлях до файлу: {file_path}")
    except (OSError, PermissionError) as e:
        print(f"Помилка при записі у файл: {e}")


# Пункт 4
def read_users_db():
    """Зчитує користувачів з csv та повертає список кортежів"""
    base_dir = os.path.dirname(__file__)
    file_path = os.path.join(base_dir, "data", "users.csv")
    db = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                username, hash_value = line.strip().split(",")
                db.append((username, hash_value))

        print("\nБаза даних користувачів:")
        print(f"{'Логін':<15} | {'Хеш пароля'}")
        print("-" * 75)
        for user, pwd_hash in db:
            print(f"{user:<15} | {pwd_hash}")
        return db

    except FileNotFoundError:
        print(f"Помилка: Файл {file_path} не знайдено.")
        return []
    except OSError as e:
        print(f"Помилка читання файлу: {e}")
        return []


# Пункт 6
def log_event(func):
    def wrapper(*args, **kwargs):
        username = args[0] if args else "unknown"
        result_status = "failure"

        try:
            result = func(*args, **kwargs)
            if result:
                result_status = "success"
            return result
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "args": args,
                "kwargs": kwargs,
            }

            base_dir = os.path.dirname(__file__)
            log_file = os.path.join(base_dir, "data", "log.json")

            logs = []
            if os.path.exists(log_file):
                try:
                    with open(log_file, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, OSError):
                    logs = []

            logs.append(log_entry)
            try:
                with open(log_file, "w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4)
            except OSError as e:
                print(f"Помилка запису логу: {e}")

    return wrapper


# Пункт 5
@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін або пароль не можуть бути порожніми")

    input_hash = generate_hash(password, PERSONAL_SALT)

    for db_user, db_hash in users_db:
        if db_user == username:
            return db_hash == input_hash

    return False  # Якщо користувача не знайдено


# Пункт 7 + 8
def main():
    print("Запуск головної функції main")
    try:
        create_users(users_to_register)  # Створення БД

        global users_db
        users_db = read_users_db()  # Завантаження БД

        # Тест входу
        print("\nТест входу:")
        print("Вхід admin (правильний пароль):", login("admin", "adminadmin123"))
        print("Вхід admin (неправильний пароль):", login("admin", "adminadmin321"))
        # login("admin", "")

    # Перехоплення помилок
    except ValidationError as e:
        print(f"Помилка валідації: {e}")
    except ValueError as e:
        print(f"Некоректне значення: {e}")
    except (OSError, FileNotFoundError, PermissionError) as e:
        print(f"Помилка роботи з файлами: {e}")
    except Exception as e:  # noqa: BLE001
        print(f"Невідома помилка: {e}")


if __name__ == "__main__":
    main()
