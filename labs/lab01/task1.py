import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

print(f"Студент: {STUDENT_NAME}\nГрупа: {GROUP_NAME}\nВаріант: {VARIANT_NUMBER}")
print()

passwords = [
    "Hello123!",
    "simple",
    "CompL3x@Pass",
    "password",
    "Str0ng#2023",
    "weak",
    "MySecur3!",
    "12345",
    "Advanced@1",
    "basic",
]
criteria = {
    "min_length": 10,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
forbidden_passwords = {"password", "simple", "weak", "basic", "12345", "hello"}

# Пункт 3
for i in range(3):
    random_index = random.randint(0, len(passwords) - 1)
    passwords.append(passwords[random_index])

# Пункт 4 + 5
print(f"{'Пароль':<15} | {'Статус'}")
print("-" * 30)

# Наявність різних типів символів
for password in passwords:
    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(not char.isalnum() for char in password)

    # Підрахунок скільки груп використано
    criteria_check = sum([has_digit, has_upper, has_lower, has_special])
    is_unique = passwords.count(password) == 1

    # Оцінка
    if password in forbidden_passwords or len(password) < criteria["min_length"]:
        status = "Заборонений"
    elif (
        criteria_check == 4
        and len(password) >= criteria["min_length"] + 4
        and is_unique
    ):
        status = "Дуже сильний"
    elif criteria_check == 4:
        status = "Сильний"
    elif criteria_check > 1:
        status = "Середній"
    else:
        status = "Слабкий"

    print(f"{password:<15} | {status}")
