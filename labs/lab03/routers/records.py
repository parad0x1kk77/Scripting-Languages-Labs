import sqlite3
from typing import Literal

from fastapi import APIRouter, HTTPException, Path, Query, status

from .. import repository, schemas

router = APIRouter(prefix="/records", tags=["records"])


def handle_integrity_error(e: sqlite3.IntegrityError):
    error_msg = str(e).lower()
    if "foreign key" in error_msg:
        raise HTTPException(status_code=404, detail="Category not found")
    raise HTTPException(status_code=409, detail="Record with this code already exists")


@router.get(
    "",
    response_model=list[schemas.RecordRead],
    summary="Список записів із фільтрами",
)
def get_records(
    category_id: int | None = Query(
        None, ge=1, description="Лише записи цієї категорії"
    ),
    status: Literal["new", "in_progress", "done"] | None = Query(
        None, description="Лише записи з цим статусом"
    ),
    min_value: float | None = Query(None, ge=0, le=10, description="Мінімальна оцінка"),
    q: str | None = Query(
        None,
        min_length=1,
        max_length=120,
        description="Буквальний підрядок у title",
    ),
    limit: int = Query(20, ge=1, le=100, description="Максимум записів"),
    offset: int = Query(0, ge=0, description="Скільки записів пропустити"),
):
    return repository.get_records(category_id, status, min_value, q, limit, offset)


@router.get(
    "/{record_id}",
    response_model=schemas.RecordRead,
    summary="Отримати запис за id",
    responses={404: {"description": "Запис не знайдено"}},
)
def get_record(record_id: int = Path(ge=1, description="Ідентифікатор запису")):
    record = repository.get_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return record


@router.post(
    "",
    response_model=schemas.RecordRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити запис",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Запис із таким code вже існує"},
    },
)
def create_record(record: schemas.RecordCreate):
    try:
        rec_id = repository.create_record(
            record.code, record.title, record.category_id, record.value, record.status
        )
        return repository.get_record(rec_id)
    except sqlite3.IntegrityError as e:
        handle_integrity_error(e)


@router.put(
    "/{record_id}",
    response_model=schemas.RecordRead,
    summary="Повністю замінити запис",
    responses={
        404: {"description": "Запис або категорію не знайдено"},
        409: {"description": "Запис із таким code вже існує"},
    },
)
def update_record(
    record: schemas.RecordReplace,
    record_id: int = Path(ge=1, description="Ідентифікатор запису"),
):
    try:
        success = repository.update_record(
            record_id,
            record.code,
            record.title,
            record.category_id,
            record.value,
            record.status,
        )
        if not success:
            raise HTTPException(status_code=404, detail="Record not found")
        return repository.get_record(record_id)
    except sqlite3.IntegrityError as e:
        handle_integrity_error(e)


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити запис",
    responses={404: {"description": "Запис не знайдено"}},
)
def delete_record(record_id: int = Path(ge=1, description="Ідентифікатор запису")):
    success = repository.delete_record(record_id)
    if not success:
        raise HTTPException(status_code=404, detail="Record not found")


@router.post(
    "/bulk",
    response_model=list[schemas.RecordRead],
    status_code=status.HTTP_201_CREATED,
    summary="Пакетне створення записів",
    responses={
        404: {"description": "Одну з категорій не знайдено, пакет не збережено"},
        409: {"description": "Дублікат code, пакет не збережено"},
    },
)
def bulk_create_records(records: list[schemas.RecordCreate]):
    if not (1 <= len(records) <= 100):
        raise HTTPException(
            status_code=422,
            detail="Bulk package must contain between 1 and 100 records",
        )

    records_dicts = [rec.model_dump() for rec in records]
    try:
        created_records = repository.bulk_create_records(records_dicts)
        return created_records
    except sqlite3.IntegrityError as e:
        handle_integrity_error(e)