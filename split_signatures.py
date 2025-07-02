import json
import math

# Путь к исходному файлу
INPUT_FILE = "assets/signatures_merged.json"

# Префикс для новых файлов
OUTPUT_PREFIX = "assets/signatures_part"

# Сколько частей сделать
NUM_PARTS = 3

# Читаем исходный JSON
with open(INPUT_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

# Получаем все ключи верхнего уровня
keys = list(data.keys())
total = len(keys)
chunk_size = math.ceil(total / NUM_PARTS)

for i in range(NUM_PARTS):
    part_keys = keys[i*chunk_size : (i+1)*chunk_size]
    part_data = {k: data[k] for k in part_keys}
    output_file = f"{OUTPUT_PREFIX}{i+1}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(part_data, f, ensure_ascii=False, indent=2)
    print(f"Создан файл {output_file} с {len(part_keys)} элементами.")

print("Готово!")
