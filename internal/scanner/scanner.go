// ключевой пакет, который описывает контракт сканеров
package scanner

import "context"

// Result описывает вывод любого сканера.
type Result struct {
	File      string // абсолютный путь к файлу
	Malicious bool   // true, если обнаружена угроза
	Reason    string // пояснение (matched hash, yara-rule …)
}

// Scanner — общий контракт: любой механизм детекции обязан реализовать Scan.
type Scanner interface {
	// Scan анализирует файл по пути path.
	//   ctx  – контекст отмены/таймаута;
	//   path – путь к проверяемому файлу.
	// Возвращает Result и возможную ошибку чтения/анализа.
	Scan(ctx context.Context, path string) (Result, error)
}
