// ключевой пакет, который описывает контракт сканеров
package scanner

import "context"

// Result описывает результат сканирования одного файла.
type Result struct {
	File      string // абсолютный путь к файлу
	Malicious bool   // true, если обнаружена угроза
	Reason    string // пояснение (matched hash и т.д.)
}

// Scanner — интерфейс для всех сканеров, реализующих метод Scan.
type Scanner interface {
	// Scan анализирует файл по указанному пути и возвращает результат.
	Scan(ctx context.Context, path string) (Result, error)
}
