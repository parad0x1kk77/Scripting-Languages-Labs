from contextlib import asynccontextmanager
from fastapi import FastAPI
from .database import initialize_database
from .routers import categories, records
import shared.student as student_data

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        initialize_database()
        print("База даних успішно ініціалізована.")
    except Exception as e:
        print(f"Помилка під час ініціалізації бази даних: {e}")
    yield

app = FastAPI(
    title="Реєстр вразливостей мережевих сервісів",
    description="""
    API для обліку та перевірки мережевих сервісів.
    Категорія визначає групу сервісів: 
    value — оцінку небезпеки (одиниця вимірювання: score) 
    status — стан опрацювання.
    """,
    version="1.0.0"
)

app.include_router(categories.router)
app.include_router(records.router)

@app.get("/ping", tags=["system"])
def ping():
    return {"status": "ok"}

@app.get("/student", tags=["system"])
def get_student():
    return {
        "student_name": student_data.STUDENT_NAME,
        "group_name": student_data.GROUP_NAME,
        "variant_number": student_data.VARIANT_NUMBER
    }