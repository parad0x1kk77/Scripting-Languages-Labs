import argparse
import hashlib
import json
import logging
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

print(f"Студент: {STUDENT_NAME}\nГрупа: {GROUP_NAME}\nВаріант: {VARIANT_NUMBER}\n")

# Власний логер, вимога Ruff
logger = logging.getLogger(__name__)

# Пункт 1
@dataclass
class FileInfo:
    filepath: str
    file_hash: str
    size: int
    mod_date: str


# Пункт 2
def calculate_file_hash(filepath: Path) -> str:
    sha256_hash = hashlib.sha256()
    # Блоками по 4 КБ
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# Пункт 3
def scan_directory(directory: Path) -> dict[str, FileInfo]:
    scanned_files = {}
    # rglob обходить усі підпапки
    for path in directory.rglob("*"):
        if path.is_file():
            stat = path.stat()
            file_hash = calculate_file_hash(path)
            # Час зміни рядком
            mod_time = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()

            # Ключ - відносний шлях, не залежить від місця папки
            rel_path = str(path.relative_to(directory))

            scanned_files[rel_path] = FileInfo(
                filepath=rel_path,
                file_hash=file_hash,
                size=stat.st_size,
                mod_date=mod_time,
            )
    return scanned_files


# Пункт 4
def save_baseline(baseline_path: Path, scanned_files: dict[str, FileInfo]):
    data_to_save = {path: asdict(info) for path, info in scanned_files.items()}
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(data_to_save, f, indent=4)
    logger.info(f"Еталонний файл успішно збережено: {baseline_path}")


def load_baseline(baseline_path: Path) -> dict[str, FileInfo]:
    if not baseline_path.exists():
        logger.error(f"Файл еталону не знайдено: {baseline_path}")
        sys.exit(1)

    with open(baseline_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Список з архіву
    if isinstance(data, list):
        result = {}
        for info in data:
            # Ключі архіву
            file_info = FileInfo(
                filepath=info["path"],
                file_hash=info["sha256"],
                size=info["size"],
                mod_date=info["modified"],
            )
            # Вигляд слешів
            norm_path = str(Path(info["path"]))
            result[norm_path] = file_info
        return result
    # Власний словник
    else:
        return {path: FileInfo(**info) for path, info in data.items()}


# Пункт 5
def check_integrity(baseline: dict[str, FileInfo], current: dict[str, FileInfo]):
    print("\n=== File Integrity Inspection Summary ===")

    unchanged = 0
    modified = []
    deleted = []
    created = []

    # Поточні файли проти зразкових
    for rel_path, current_info in current.items():
        if rel_path in baseline:
            baseline_info = baseline[rel_path]
            # Хеші різні
            if current_info.file_hash != baseline_info.file_hash:
                modified.append(
                    (rel_path, baseline_info.file_hash, current_info.file_hash)
                )
            else:
                unchanged += 1
        else:
            # Немає в зразку
            created.append((rel_path, current_info.size))

    # Зниклі файли
    for rel_path in baseline:
        if rel_path not in current:
            deleted.append(rel_path)

    # Статистика
    print(f"Total monitored files : {len(current) + len(deleted)}")
    print(f"Unchanged files       : {unchanged}")
    print(f"Modified files        : {len(modified)}")
    print(f"Created files         : {len(created)}")
    print(f"Deleted files         : {len(deleted)}\n")

    # Аномалії
    if modified or created or deleted:
        print("=== Detected Anomalies ===")
        for path, exp_hash, act_hash in modified:
            msg = f"[MODIFIED] {path}\n  Expected SHA-256 : {exp_hash}\n  Actual SHA-256   : {act_hash}"
            print(msg)
            logger.warning(f"Файл змінено: {path}")

        for path, size in created:
            msg = f"[CREATED]  {path} (Size: {size} B)"
            print(msg)
            logger.warning(f"Створено новий файл: {path}")

        for path in deleted:
            msg = f"[DELETED]  {path}"
            print(msg)
            logger.warning(f"Файл видалено: {path}")

        print("\n[WARNING] Security alerts detected! Check audit log.")
    else:
        print("=== Status ===")
        print("[OK] No anomalies detected. Integrity intact.")
        logger.info("Перевірка завершена. Порушень не виявлено.")


# Пункт 6
def setup_logging(log_file: str):
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(asctime)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),  # І в консоль
        ],
    )


# Пункт 7
def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitor (FIM)")
    parser.add_argument(
        "--dir", required=True, type=Path, help="Директорія для моніторингу"
    )
    parser.add_argument(
        "--baseline", required=True, type=Path, help="Шлях до файлу baseline.json"
    )
    parser.add_argument(
        "--mode", required=True, choices=["generate", "check"], help="Режим роботи"
    )
    parser.add_argument(
        "--log-file", required=True, type=str, help="Файл журналу логування"
    )

    args = parser.parse_args()

    setup_logging(args.log_file)

    if not args.dir.exists() or not args.dir.is_dir():
        logger.error(f"Директорія не знайдена: {args.dir}")
        sys.exit(1)

    if args.mode == "generate":
        logger.info(f"Режим генерації. Сканування директорії: {args.dir}")
        scanned = scan_directory(args.dir)
        save_baseline(args.baseline, scanned)

    elif args.mode == "check":
        logger.info(f"Loading baseline file: {args.baseline}")
        logger.info(f"Scanning directory: {args.dir}")

        baseline_data = load_baseline(args.baseline)
        current_data = scan_directory(args.dir)

        check_integrity(baseline_data, current_data)


if __name__ == "__main__":
    main()