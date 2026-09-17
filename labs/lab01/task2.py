import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

print(f"Студент: {STUDENT_NAME}\nГрупа: {GROUP_NAME}\nВаріант: {VARIANT_NUMBER}")
print()

users = {
    "sysadmin02": {
        "role": "system_admin",
        "clearance": 4,
        "department": "Infrastructure",
        "active": True,
    },
    "analyst234": {
        "role": "security_analyst",
        "clearance": 3,
        "department": "SOC",
        "active": True,
    },
    "developer567": {
        "role": "developer",
        "clearance": 2,
        "department": "Development",
        "active": True,
    },
    "intern890": {"role": "intern", "clearance": 1, "department": "HR", "active": True},
    "external123": {
        "role": "external",
        "clearance": 1,
        "department": "Vendor",
        "active": False,
    },
}
resources = [
    ("prod_database", 4),
    ("dev_environment", 2),
    ("documentation", 1),
    ("source_code", 3),
    ("server_configs", 4),
    ("test_data", 2),
    ("compliance_docs", 3),
    ("system_logs", 4),
    ("project_files", 2),
    ("public_wiki", 1),
]
security_levels = ("Open", "Internal", "Restricted", "Top Secret")
blocked_users = {"external123", "old_account", "test_user"}

# Пункт 2
print("Список ресурсів системи:")
for resource_name, resource_level in resources:
    level_name = security_levels[resource_level - 1]
    print(f"Ресурс: {resource_name:<15} | Рівень: {level_name}")

users_test = list(users.keys()) + list(blocked_users) + ["unknown"]

# Пункт 3
print("\nРезультати перевірки доступу:")
for username in users_test:
    for resource_name, resource_level in resources:
        # 1. Якщо користувача немає в системі
        if username not in users:
            status = "DENY (User not found)"

        # 2. Якщо користувач є у списку заблокованих
        elif username in blocked_users:
            status = "DENY (User is blocked)"

        # 3. Якщо обліковий запис неактивний
        elif users[username].get("active") == False:
            status = "DENY (Account inactive)"

        # 4. Якщо рівень допуску достатній (більший або дорівнює)
        elif users[username].get("clearance", 0) >= resource_level:
            status = "ALLOW"

        # 5. Якщо рівень допуску менший за рівень ресурсу
        else:
            status = "DENY (Insufficient clearance)"

        print(f"user={username} resource={resource_name} -> {status}")
