import json
import glob

# Путь к частям
parts = sorted(glob.glob("signatures_part*.json"))

result = {}

for part in parts:
    with open(part, "r", encoding="utf-8") as f:
        data = json.load(f)
        result.update(data)

with open("signatures_merged.json", "w", encoding="utf-8") as f:
    json.dump(result, f, ensure_ascii=False, indent=2)

print(f"Объединено {len(parts)} файлов в assets/signatures_merged.json")
