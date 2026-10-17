import sqlite3
from fastapi import APIRouter, HTTPException, status, Query
from typing import List, Optional
from .. import repository, schemas

router = APIRouter(prefix="/records", tags=["records"])


def handle_integrity_error(e: sqlite3.IntegrityError):
    error_msg = str(e).lower()
    if "foreign key" in error_msg:
        raise HTTPException(status_code=404, detail="Category not found")
    raise HTTPException(status_code=409, detail="Record with this code already exists")


@router.get("", response_model=List[schemas.RecordRead])
def get_records(
        category_id: Optional[int] = Query(None, ge=1),
        status: Optional[str] = None,
        min_value: Optional[float] = None,
        q: Optional[str] = Query(None, min_length=1, max_length=120),
        limit: int = Query(20, ge=1, le=100),
        offset: int = Query(0, ge=0)
):
    return repository.get_records(category_id, status, min_value, q, limit, offset)


@router.get("/{record_id}", response_model=schemas.RecordRead)
def get_record(record_id: int):
    record = repository.get_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return record


@router.post("", response_model=schemas.RecordRead, status_code=status.HTTP_201_CREATED)
def create_record(record: schemas.RecordCreate):
    try:
        rec_id = repository.create_record(
            record.code, record.title, record.category_id, record.value, record.status
        )
        return repository.get_record(rec_id)
    except sqlite3.IntegrityError as e:
        handle_integrity_error(e)


@router.put("/{record_id}", response_model=schemas.RecordRead)
def update_record(record_id: int, record: schemas.RecordReplace):
    try:
        success = repository.update_record(
            record_id, record.code, record.title, record.category_id, record.value, record.status
        )
        if not success:
            raise HTTPException(status_code=404, detail="Record not found")
        return repository.get_record(record_id)
    except sqlite3.IntegrityError as e:
        handle_integrity_error(e)


@router.delete("/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_record(record_id: int):
    success = repository.delete_record(record_id)
    if not success:
        raise HTTPException(status_code=404, detail="Record not found")


@router.post("/bulk", response_model=List[schemas.RecordRead], status_code=status.HTTP_201_CREATED)
def bulk_create_records(records: List[schemas.RecordCreate]):
    if not (1 <= len(records) <= 100):
        raise HTTPException(status_code=422, detail="Bulk package must contain between 1 and 100 records")

    records_dicts = [rec.model_dump() for rec in records]
    try:
        created_records = repository.bulk_create_records(records_dicts)
        return created_records
    except sqlite3.IntegrityError as e:
        handle_integrity_error(e)