import hashlib
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

print(f"Студент: {STUDENT_NAME}\nГрупа: {GROUP_NAME}\nВаріант: {VARIANT_NUMBER}")
print()


class User:
    def __init__(
        self, username: str, email: str, role: str = "user", active: bool = True, permissions: set | None = None
    ):
        self.username = username
        self.email = email
        self.role = role
        self.active = active
        # Приватні атрибути для пароля
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, value: str):
        # Перевірка формату
        pattern = r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError(f"Невірний формат email: {value}")
        self._email = value

    def set_password(self, password: str):
        # Сіль
        self.__password_salt = os.urandom(16)

        # Хешування
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            100000,  # Ітерації
        )

    def check_password(self, password: str) -> bool:
        if not self.__password_hash or not self.__password_salt:
            return False

        # Хеш для порівняння
        test_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, 100000
        )
        # Порівняння
        import hmac

        return hmac.compare_digest(self.__password_hash, test_hash)

    def deactivate(self):
        self.active = False

    def __str__(self):
        status = "Active" if self.active else "Inactive"
        return (
            f"User({self.username}, {self.email}, Role: {self.role}, Status: {status})"
        )


class Admin(User):
    def __init__(
        self, username: str, email: str, active: bool = True, permissions: set | None = None
    ):
        super().__init__(username, email, role="admin", active=active)
        # Пуста множина за замовчуванням
        self.permissions = permissions if permissions is not None else set()

    def grant_permission(self, permission: str):
        self.permissions.add(permission)

    def revoke_permission(self, permission: str):
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self):
        base_str = super().__str__()
        return f"{base_str}, Permissions: {self.permissions}"


class Session:
    def __init__(self, ip: str):
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self):
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("Таймаут повинен бути позитивним числом")

        now = datetime.now(timezone.utc)
        # Перевірка таймауту
        return (now - self.last_activity) <= timedelta(seconds=timeout_sec)


# Формат запису журналу
@dataclass
class AuditEntry:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self):
        self.records = []

    def add_log(self, username: str, action: str):
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc), username=username, action=action
        )
        self.records.append(entry)

    def show_all(self):
        for record in self.records:
            print(
                f"[{record.timestamp.isoformat()}] {record.username} -> {record.action}"
            )


SESSION_TIMEOUT_SEC = 900  # 15 хвилин


class UserAccount:
    def __init__(self, user: User, audit_log: AuditLog = None):
        self.user = user
        self.session: Session | None = None
        # за замовчуванням
        self.audit_log = audit_log if audit_log else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        # перевірка пароля та активності
        if (
            self.user.active
            and self.user.username == username
            and self.user.check_password(password)
        ):
            self.session = Session(ip)
            self.session.touch()
            self.audit_log.add_log(username, "login_success")
            return True
        else:
            self.audit_log.add_log(username, "login_failure")
            return False

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False

        if self.session.is_active(SESSION_TIMEOUT_SEC):
            return True
        else:
            # видалення старої сесії
            self.session = None
            return False

    def logout(self):
        if self.session:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, key: str):
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit_log":
            return self.audit_log
        else:
            raise KeyError(f"Невідомий ключ: {key}")

    def __setitem__(self, key: str, value):
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення має бути об'єктом класу User")
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError("Значення має бути об'єктом класу Session")
            self.session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError("Значення має бути об'єктом класу AuditLog")
            self.audit_log = value
        else:
            raise KeyError(f"Невідомий ключ: {key}")
