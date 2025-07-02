package signature

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"localantivirus/internal/scanner"
	"localantivirus/internal/signaturedb"
	"os"
)

// SigScanner реализует интерфейс Scanner и ищет вредоносные файлы по хеш-сигнатурам.
type SigScanner struct {
	DB *signaturedb.DB // база сигнатур
}

// New создает новый SigScanner, связанный с указанной базой сигнатур.
func New(db *signaturedb.DB) *SigScanner {
	return &SigScanner{DB: db}
}

// Scan вычисляет хеши файла и ищет их в базе сигнатур.
func (s *SigScanner) Scan(ctx context.Context, path string) (scanner.Result, error) {
	file, err := os.Open(path) // открыть файл
	if err != nil {
		return scanner.Result{File: path}, err
	}
	defer file.Close() // закрыть при выходе

	// Считаем все три хеша
	hashers := map[string]func() hash.Hash{
		"md5":    md5.New,
		"sha1":   sha1.New,
		"sha256": sha256.New,
	}
	hashes := make(map[string]string)
	content, err := io.ReadAll(file)
	if err != nil {
		return scanner.Result{File: path}, err
	}
	for typ, newHasher := range hashers {
		h := newHasher()
		h.Write(content)
		hashes[typ] = hex.EncodeToString(h.Sum(nil))
	}

	res := scanner.Result{
		File:      path,
		Malicious: false,
	}
	if s.DB == nil {
		res.Reason = "Signature DB is not initialized"
		return res, nil
	}
	for typ, sum := range hashes {
		if s.DB.Exists(typ, sum) {
			res.Malicious = true
			res.Reason = "Matched " + typ + " hash " + sum
			break
		}
	}

	return res, nil
}
