package main

import (
	"context"
	"flag"
	"fmt"
	"localantivirus/internal/filewalk"
	"localantivirus/internal/scanner/signature"
	"localantivirus/internal/signaturedb"
	"log"
	"os"
	"time"

	"github.com/schollz/progressbar/v3"
)

// main — точка входа в приложение. Запускает сканирование файлов на вредоносные сигнатуры.
func main() {
	// --- 1. флаги командной строки ---
	dir := flag.String("dir", ".", "directory to scan")
	sigPath := flag.String("sigfile", "assets/signatures_merged.json", "path to signature JSON")
	tOut := flag.Duration("timeout", 5*time.Minute, "overall scan timeout")
	flag.Parse()

	// --- 2. контекст с таймаутом ---
	ctx, cancel := context.WithTimeout(context.Background(), *tOut)
	defer cancel()

	// --- 3. загружаем базу сигнатур ---
	db, err := signaturedb.LoadFromJSON(*sigPath)
	if err != nil {
		log.Fatalf("cannot load signatures: %v", err)
	}

	// --- 4. создаём сканер и запускаем обход ---
	sigScan := signature.New(db)
	results, err := filewalk.WalkAndScan(ctx, *dir, sigScan)
	if err != nil {
		log.Fatalf("scan failed: %v", err)
	}

	bar := progressbar.Default(int64(len(results)))

	// --- 5. выводим результаты ---
	infected := 0
	for _, r := range results {
		if r.Malicious {
			infected++
			fmt.Printf("⚠️  %s — %s\n", r.File, r.Reason)
		}
		bar.Add(1)
	}

	fmt.Printf("Scan finished. Files checked: %d, threats: %d\n", len(results), infected)
	if infected > 0 {
		os.Exit(2) // non-zero exit-code, можно использовать в CI
	}
}
