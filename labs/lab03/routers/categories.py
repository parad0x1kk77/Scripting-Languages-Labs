import sqlite3

from fastapi import APIRouter, HTTPException, Path, status

from .. import repository, schemas

router = APIRouter(prefix="/categories", tags=["categories"])


@router.get(
    "",
    response_model=list[schemas.CategoryRead],
    summary="Список категорій",
)
def get_categories():
    return repository.get_categories()


@router.post(
    "",
    response_model=schemas.CategoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити категорію",
    responses={409: {"description": "Категорія з такою назвою вже існує"}},
)
def create_category(category: schemas.CategoryCreate):
    try:
        cat_id = repository.create_category(category.name)
        return {"id": cat_id, "name": category.name}
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409, detail="Category with this name already exists"
        )


@router.delete(
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить записи"},
    },
)
def delete_category(
    category_id: int = Path(ge=1, description="Ідентифікатор категорії"),
):
    try:
        success = repository.delete_category(category_id)
        if not success:
            raise HTTPException(status_code=404, detail="Category not found")
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409, detail="Cannot delete category containing records"
        )
