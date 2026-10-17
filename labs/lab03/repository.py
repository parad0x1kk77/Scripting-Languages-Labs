import sqlite3
from contextlib import closing
from typing import Optional, List, Dict, Any
from .database import get_connection


def get_categories() -> List[Dict[str, Any]]:
    with closing(get_connection()) as connection:
        cursor = connection.execute("SELECT id, name FROM categories ORDER BY id ASC")
        return [{"id": row[0], "name": row[1]} for row in cursor.fetchall()]


def create_category(name: str) -> int:
    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute("INSERT INTO categories (name) VALUES (?)", (name,))
            return cursor.lastrowid


def delete_category(category_id: int) -> bool:
    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute("DELETE FROM categories WHERE id = ?", (category_id,))
            return cursor.rowcount > 0


def get_record(record_id: int) -> Optional[Dict[str, Any]]:
    query = """
        SELECT r.id, r.code, r.title, r.category_id, c.name as category_name, r.value, r.status
        FROM records r
        JOIN categories c ON r.category_id = c.id
        WHERE r.id = ?
    """
    with closing(get_connection()) as connection:
        cursor = connection.execute(query, (record_id,))
        row = cursor.fetchone()
        if row:
            return {
                "id": row[0], "code": row[1], "title": row[2],
                "category_id": row[3], "category_name": row[4],
                "value": row[5], "status": row[6]
            }
        return None


def get_records(
        category_id: Optional[int] = None,
        status: Optional[str] = None,
        min_value: Optional[float] = None,
        q: Optional[str] = None,
        limit: int = 20,
        offset: int = 0
) -> List[Dict[str, Any]]:
    query = """
        SELECT r.id, r.code, r.title, r.category_id, c.name as category_name, r.value, r.status
        FROM records r
        JOIN categories c ON r.category_id = c.id
        WHERE 1=1
    """
    params = []
    if category_id is not None:
        query += " AND r.category_id = ?"
        params.append(category_id)
    if status is not None:
        query += " AND r.status = ?"
        params.append(status)
    if min_value is not None:
        query += " AND r.value >= ?"
        params.append(min_value)
    if q is not None:
        query += " AND instr(r.title, ?) > 0"
        params.append(q)

    query += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(get_connection()) as connection:
        cursor = connection.execute(query, tuple(params))
        return [
            {
                "id": row[0], "code": row[1], "title": row[2],
                "category_id": row[3], "category_name": row[4],
                "value": row[5], "status": row[6]
            }
            for row in cursor.fetchall()
        ]


def create_record(code: str, title: str, category_id: int, value: float, status: str) -> int:
    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute(
                """INSERT INTO records (code, title, category_id, value, status)
                   VALUES (?, ?, ?, ?, ?)""",
                (code, title, category_id, value, status)
            )
            return cursor.lastrowid


def update_record(record_id: int, code: str, title: str, category_id: int, value: float, status: str) -> bool:
    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute(
                """UPDATE records
                   SET code = ?, title = ?, category_id = ?, value = ?, status = ?
                   WHERE id = ?""",
                (code, title, category_id, value, status, record_id)
            )
            return cursor.rowcount > 0


def delete_record(record_id: int) -> bool:
    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute("DELETE FROM records WHERE id = ?", (record_id,))
            return cursor.rowcount > 0


def bulk_create_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    created = []
    with closing(get_connection()) as connection:
        with connection:
            for rec in records:
                cursor = connection.execute(
                    """INSERT INTO records (code, title, category_id, value, status)
                       VALUES (?, ?, ?, ?, ?)""",
                    (rec["code"], rec["title"], rec["category_id"], rec["value"], rec["status"])
                )
                rec_id = cursor.lastrowid

                cat_cursor = connection.execute("SELECT name FROM categories WHERE id = ?", (rec["category_id"],))
                cat_row = cat_cursor.fetchone()
                cat_name = cat_row[0] if cat_row else ""

                created.append({
                    "id": rec_id,
                    "code": rec["code"],
                    "title": rec["title"],
                    "category_id": rec["category_id"],
                    "category_name": cat_name,
                    "value": rec["value"],
                    "status": rec["status"]
                })
    return created