package filewalk

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"localantivirus/internal/scanner"
)

// WalkAndScan рекурсивно обходит root-директорию и проверяет каждый
// найденный файл всеми переданными сканерами. Работает параллельно
// (одна горутина на файл) и реагирует на отмену ctx.
func WalkAndScan(
	ctx context.Context,
	root string,
	scanners ...scanner.Scanner,
) ([]scanner.Result, error) {
	// 1. Если сканеров нет — ничего делать не нужно.
	if len(scanners) == 0 {
		return nil, nil
	}

	// 2. Канал для результатов (+-64 буфер, чтобы не блокироваться сразу).
	results := make(chan scanner.Result, 64)

	// 3. Счётчик активных горутин-сканеров.
	var wg sync.WaitGroup

	// 4. Срез, куда «собиратель» сложит все результаты.
	collected := make([]scanner.Result, 0, 128)

	// 5. Горутина-«собиратель»: читает канал и накапливает.
	go func() {
		for r := range results {
			collected = append(collected, r)
		}
	}()

	// 6. Реальный обход файловой системы.
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		// a) Если сама WalkDir столкнулась с ошибкой — передаём наверх.
		if err != nil {
			return err
		}

		// b) Уважаем отмену контекста.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// c) Пропускаем директории; интересуют только файлы.
		if d.IsDir() {
			return nil
		}

		// d) Проверим, что это обычный файл (без сокетов, ссылок и т.п.).
		info, statErr := os.Stat(path)
		if statErr != nil || !info.Mode().IsRegular() {
			return nil
		}

		// e) Запускаем сканирование файла в отдельной горутине.
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			for _, sc := range scanners {
				r, err := sc.Scan(ctx, p)
				if err != nil {
					// Ошибка чтения → фиксируем как «не-заражен», но с текстом ошибки.
					results <- scanner.Result{File: p, Malicious: false, Reason: err.Error()}
					return
				}
				results <- r
			}
		}(path)

		return nil
	})

	// 7. Ждём завершения всех сканирующих горутин и закрываем канал.
	wg.Wait()
	close(results)

	return collected, walkErr
}
