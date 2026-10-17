import sqlite3
from fastapi import APIRouter, HTTPException, status
from typing import List
from .. import repository, schemas

router = APIRouter(prefix="/categories", tags=["categories"])

@router.get("", response_model=List[schemas.CategoryRead])
def get_categories():
    return repository.get_categories()

@router.post("", response_model=schemas.CategoryRead, status_code=status.HTTP_201_CREATED)
def create_category(category: schemas.CategoryCreate):
    try:
        cat_id = repository.create_category(category.name)
        return {"id": cat_id, "name": category.name}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Category with this name already exists")

@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_category(category_id: int):
    try:
        success = repository.delete_category(category_id)
        if not success:
            raise HTTPException(status_code=404, detail="Category not found")
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Cannot delete category containing records")