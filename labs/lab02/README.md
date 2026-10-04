# Лабораторна робота №2

Варіант 2: File Integrity Monitor (FIM).

- `task1.py` - ООП-модель користувачів, сесій і журналу аудиту.
- `task2.py` - утиліта перевірки цілісності файлів (SHA-256).

## Встановлення

```bash
  pip install -r requirements.txt
```

## Структура

```
labs/lab02/
main.py       # демо Завдання 1
task1.py
task2.py
data/
    monitored/      # каталог для перевірки
    baseline.json   # еталон
    fim_audit.log   # журнал
```

## Запуск

З кореня репозиторію.

Завдання 1:

```bash
  python -m labs.lab02.main demo
```

Завдання 2: Створення еталону

```bash
  python -m labs.lab02.task2 --dir labs/lab02/data/monitored --baseline labs/lab02/data/baseline.json --mode generate --log-file labs/lab02/data/fim_audit.log
```

Завдання 2: Перевірка
```bash
  python -m labs.lab02.task2 --dir labs/lab02/data/monitored --baseline labs/lab02/data/baseline.json --mode check --log-file labs/lab02/data/fim_audit.log
```

## Параметри task2

- `--dir` - каталог для сканування
- `--baseline` - шлях до baseline.json
- `--mode` - generate або check
- `--log-file` - файл журналу

Параметри обов'язкові.

## Результат перевірки

- **Modified** - хеш змінився
- **Created** - файлу немає в еталоні
- **Deleted** - файл зник

## Помилки
Якщо каталог або еталон не знайдено, програма пише `ERROR` Code 1.