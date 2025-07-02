# LocalAntivirus

**LocalAntivirus** — это простой локальный антивирус для сканирования файлов на наличие вредоносных сигнатур по хешам (MD5, SHA1, SHA256).

---

## 📦 Структура проекта
localantivirus/
  assets/
    signatures_part1.json
    signatures_part2.json
    signatures_part3.json
    merge_signatures.py
  cmd/
    macav/
      main.go
  internal/
    filewalk/
      walk.go
    scanner/
      signature/
        signature.go
      scanner.go
    signaturedb/
      db.go
go.mod
go.sum
split_signatures.py
README.md

---

## 🚀 Быстрый старт

### 1. Клонируйте репозиторий

```sh
git clone https://github.com/BogdanAlaitsev/localantivirus.git
cd localantivirus
```

### 2. Установите Go (если ещё не установлен)

- [Инструкция по установке Go](https://golang.org/doc/install)

### 3. Соберите большой файл сигнатур из частей

Перед запуском антивируса **ОБЯЗАТЕЛЬНО** объедините части сигнатур в один файл:

```sh
python3 assets/merge_signatures.py
```

- Скрипт `merge_signatures.py` автоматически объединит все файлы `assets/signatures_part*.json` в один файл `assets/signatures_merged.json`.
- Если у вас нет Python, установите его с [официального сайта](https://www.python.org/downloads/).

### 4. Запустите сканирование

```sh
go run ./cmd/macav
```

---

## ⚙️ Аргументы командной строки

| Флаг         | Описание                                                        | Значение по умолчанию                |
|--------------|-----------------------------------------------------------------|--------------------------------------|
| `-dir`       | Директория для сканирования                                     | `.` (текущая директория)             |
| `-sigfile`   | Путь к JSON-файлу с сигнатурами                                 | `assets/signatures_merged.json`      |
| `-timeout`   | Таймаут на всё сканирование (например, `2m`, `30s`, `5m`)       | `5m` (5 минут)                       |

**Примеры:**
```sh
go run ./cmd/macav -dir=/Users/username/Downloads
go run ./cmd/macav -sigfile=assets/signatures_merged.json -timeout=10m
```

---

## 🛠️ Как работает сборка сигнатур

1. **Части сигнатур** (`signatures_part1.json`, `signatures_part2.json`, ...) хранятся в папке `assets/`.
2. **Скрипт** `merge_signatures.py` объединяет их в один файл `signatures_merged.json`.
3. **Антивирус** использует только итоговый файл `signatures_merged.json` для сканирования.

**Внимание:**  
- Не добавляйте `signatures_merged.json` в git — он уже в `.gitignore`.
- Если вы обновили или добавили новые части, обязательно пересоберите итоговый файл перед запуском!

---

## 📝 Пример использования merge_signatures.py

```sh
python3 assets/merge_signatures.py
```
- После выполнения появится файл `assets/signatures_merged.json`.

---

## 📄 Пример вывода
⚠️ /Users/username/Downloads/malware.exe — Matched sha256 hash 44d88612fea8a8f36de82e1278abb02f3f2e1f0d7bb3e9c3e9180c10d5819be
Scan finished. Files checked: 1234, threats: 1

---

## ❓ FAQ

**Q:** Почему нельзя хранить большой файл сигнатур в git?  
**A:** GitHub не позволяет хранить файлы больше 100 МБ. Поэтому файл разбит на части и собирается скриптом.

**Q:** Можно ли добавить новые сигнатуры?  
**A:** Да! Просто добавьте их в одну из частей, либо создайте новую часть, и пересоберите итоговый файл.

---

## 🧑‍💻 Контакты

Автор: [BogdanAlaitsev](https://github.com/BogdanAlaitsev)

---

## 🏁 Удачного сканирования!
