// данный код реализует хранение базы SHA-256 -> название вредоноса
package signaturedb

import (
	"encoding/json" // библиотека кодирования/декодирования JSON
	"os"            // бибилотека функций для работы с файлами
)

// DB хранит сигнатуры вредоносных файлов по хешам разных типов.
type DB struct {
	sigs map[string]map[string]string // тип хеша -> хеш -> описание
}

// функция загрузки сигнатур из JSON файла и обертка в DB
// LoadFromJSON загружает базу сигнатур из JSON-файла.
func LoadFromJSON(path string) (*DB, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Пробуем декодировать как map[string]map[string]string
	var multi map[string]map[string]string
	dec := json.NewDecoder(file)
	if err := dec.Decode(&multi); err == nil {
		return &DB{sigs: multi}, nil
	}

	// Если не получилось, пробуем старый формат (map[string]string, считаем это SHA-256)
	file.Seek(0, 0)
	var single map[string]string
	dec = json.NewDecoder(file)
	if err := dec.Decode(&single); err == nil {
		m := map[string]map[string]string{"sha256": single}
		return &DB{sigs: m}, nil
	}

	return nil, err
}

// Exists проверяет, есть ли сигнатура с данным хешем и типом в базе.
func (db *DB) Exists(hashType, hash string) bool {
	if db == nil || db.sigs == nil {
		return false
	}
	if m, ok := db.sigs[hashType]; ok {
		_, ok2 := m[hash]
		return ok2
	}
	return false
}
