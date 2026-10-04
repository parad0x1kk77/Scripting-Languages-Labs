import sys
from datetime import timedelta

from labs.lab02.task1 import SESSION_TIMEOUT_SEC, Admin, AuditLog, UserAccount


def run_demo():
    print("--- Завдання 1 ---")

    # Пункт 1
    print("\n1. Створення об'єктів:")
    audit = AuditLog()
    # Права адміністатора
    admin_user = Admin("OleksandrAdmin", "oleksandr@example.com")
    admin_user.set_password("OleksandrPass!")
    account = UserAccount(admin_user, audit)
    print(account["user"])

    # Пункт 2
    print("\n2. Спроба невдалого входу:")
    success = account.login("OleksandrAdmin", "WrongPass", "192.168.1.10")
    print("Використання неправильного пароля")
    print(f"Результат входу: {'Успіх' if success else 'Помилка'}")

    # Пункт 3
    print("\n3. Спроба успішного входу:")
    success = account.login("OleksandrAdmin", "OleksandrPass!", "192.168.1.10")
    print("Використання правильного пароля")
    print(f"Результат входу: {'Успіх' if success else 'Помилка'}")
    print(f"Автентифікований: {account.is_authenticated()}")

    # Пункт 4
    print("\n4. Зміна email із валідацією:")
    try:
        account["user"].email = "oleksandrnew@mail.com"
        print(f"Email успішно змінено на: {account['user'].email}")
        print("Спроба встановити неправильний email 'test@mail'")
        account["user"].email = "test@mail"  # Очікується ValueError
    except ValueError as e:
        print(f"ПОМИЛКА: {e}")

    # Пункт 5
    print("\n5. Робота з правами адміністратора:")
    admin_user.grant_permission("DELETE_USERS")
    print(f"Нове право: {admin_user.permissions}")
    print(f"Чи є право? {admin_user.has_permission('DELETE_USERS')}")

    # Пункт 6
    print("\n6. Імітація завершення сеансу за таймаутом:")
    if account["session"]:
        # Остання активність
        account["session"].last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 10)
        print(f"Автентифікований після таймауту? {account.is_authenticated()}")

    # Пункт 7
    print("\n7. Вихід із системи:")
    account.login("OleksandrAdmin", "OleksandrPass!", "192.168.1.10")
    account.logout()
    print(f"Автентифікований після виходу? {account.is_authenticated()}")

    # Пункт 8
    print("\n8. Журнал аудиту:")
    account["audit_log"].show_all()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        run_demo()
    else:
        print(
            "Для запуску демонстрації використайте команду: python -m labs.lab02.main demo"
        )
