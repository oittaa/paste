package main

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	charset    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	charsetLen = len(charset)
	maxAccept  = 255 - (256 % charsetLen)
	ivSize     = 12 // AES-GCM IV size in bytes
)

//go:embed templates/index.html static/script.js static/styles.css static/favicon.jpg static/highlight.min.js static/atom-one-light.min.css static/atom-one-dark.min.css
var content embed.FS

var (
	dbFile          = flag.String("db", "pastes.db", "SQLite DB file (use ':memory:' for in-mem)")
	idLength        = flag.Int("idlen", 8, "Default paste ID length")
	expDays         = flag.Int("expdays", 30, "Paste expiration days")
	cleanupInterval = flag.Duration("cleanup-interval", time.Hour, "Cleanup interval")
	maxSize         = flag.Int64("maxsize", 1<<20, "Maximum paste size in bytes (default 1MB)")
	listenAddr      = flag.String("addr", "0.0.0.0", "Listen address")
	listenPort      = flag.String("port", "8080", "Listen port")
)

type App struct {
	DB              *sql.DB
	Tmpl            *template.Template
	IDLength        int
	ExpDuration     time.Duration
	CleanupInterval time.Duration
	MaxSize         int64
}

func NewApp(dbPath string) (*App, error) {
	tmpl, err := template.ParseFS(content, "templates/index.html")
	if err != nil {
		return nil, err
	}

	if dbPath == ":memory:" {
		log.Println("Using in-memory DB")
	} else {
		log.Println("Using file DB:", dbPath)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	app := &App{
		DB:              db,
		Tmpl:            tmpl,
		IDLength:        *idLength,
		ExpDuration:     time.Duration(*expDays) * 24 * time.Hour,
		CleanupInterval: *cleanupInterval,
		MaxSize:         *maxSize,
	}

	if err := app.initDB(); err != nil {
		return nil, err
	}

	return app, nil
}

func (a *App) initDB() error {
	_, err := a.DB.Exec(`CREATE TABLE IF NOT EXISTS pastes (
		id TEXT PRIMARY KEY,
		data BLOB NOT NULL,
		iv BLOB NOT NULL,
		created DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return err
	}
	_, err = a.DB.Exec("CREATE INDEX IF NOT EXISTS idx_created ON pastes(created)")
	if err != nil {
		log.Printf("Warning: Failed to create index: %v", err)
	}
	return nil
}

func (a *App) StartCleanup() {
	go a.cleanupGoroutine()
}

func (a *App) runCleanup() {
	tx, err := a.DB.Begin()
	if err != nil {
		log.Printf("Cleanup tx begin error: %v", err)
		return
	}
	defer tx.Rollback()

	hours := int(a.ExpDuration.Hours())
	modifier := fmt.Sprintf("-%d hours", hours)
	res, err := tx.Exec("DELETE FROM pastes WHERE created < datetime('now', ?)", modifier)
	if err != nil {
		log.Printf("Cleanup delete error: %v", err)
		return
	}
	rows, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		log.Printf("Cleanup commit error: %v", err)
		return
	}
	if rows > 0 {
		log.Printf("Cleaned up %d expired pastes", rows)
	}
}

func (a *App) cleanupGoroutine() {
	a.runCleanup()

	ticker := time.NewTicker(a.CleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		a.runCleanup()
	}
}

func (a *App) Close() error {
	return a.DB.Close()
}

// SecurityHeadersMiddleware adds CSP and other hardening headers
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'self'; form-action 'none'; frame-ancestors 'none';")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// Handlers as methods on *App

func (a *App) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.Tmpl.Execute(w, nil); err != nil {
		log.Printf("Template execute error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (a *App) serveHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := a.DB.Ping(); err != nil {
		log.Printf("Health check failed: DB ping error: %v", err)
		http.Error(w, "unhealthy", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		w.Write([]byte("ok"))
	}
}

func (a *App) serveCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, a.MaxSize*3/2+8192)

	var req struct {
		Data string `json:"data"`
		IV   string `json:"iv"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
		}
		return
	}

	if int64(len(req.Data)) > a.MaxSize*2 {
		http.Error(w, "Payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	decodedData, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		http.Error(w, "Invalid data encoding", http.StatusBadRequest)
		return
	}
	if int64(len(decodedData)) > a.MaxSize {
		http.Error(w, "Oversized data", http.StatusRequestEntityTooLarge)
		return
	}

	decodedIV, err := base64.StdEncoding.DecodeString(req.IV)
	if err != nil || len(decodedIV) != ivSize {
		http.Error(w, "Invalid IV", http.StatusBadRequest)
		return
	}

	var id string
	length := a.IDLength
	maxRetries := 100
	retries := 0
	for {
		id = randString(length)
		res, err := a.DB.Exec("INSERT INTO pastes (id, data, iv) VALUES (?, ?, ?)",
			id, decodedData, decodedIV)
		if err == nil {
			rows, _ := res.RowsAffected()
			if rows == 1 {
				break
			}
		}
		retries++
		if retries >= maxRetries {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		if retries%10 == 0 {
			length++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (a *App) servePaste(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 3 || parts[1] != "p" || parts[2] == "" || len(parts[2]) > 256 {
		http.NotFound(w, r)
		return
	}
	id := parts[2]
	for _, ch := range id {
		if !strings.ContainsRune(charset, ch) {
			http.NotFound(w, r)
			return
		}
	}

	accept := r.Header.Get("Accept")
	isHTML := strings.Contains(accept, "text/html")
	w.Header().Add("Vary", "Accept")

	if isHTML {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := a.Tmpl.Execute(w, nil); err != nil {
			log.Printf("Template execute error: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	a.getPaste(w, r, id)
}

func (a *App) getPaste(w http.ResponseWriter, r *http.Request, id string) {
	var dataBlob []byte
	var ivBlob []byte
	var created time.Time
	err := a.DB.QueryRow("SELECT data, iv, created FROM pastes WHERE id = ?", id).Scan(&dataBlob, &ivBlob, &created)
	if err != nil {
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Internal error", http.StatusInternalServerError)
		}
		return
	}

	if time.Since(created) > a.ExpDuration {
		_, delErr := a.DB.Exec("DELETE FROM pastes WHERE id = ?", id)
		if delErr != nil {
			log.Printf("Failed to delete expired paste %s: %v", id, delErr)
		}
		http.Error(w, "Paste expired", http.StatusGone)
		return
	}

	dataB64 := base64.StdEncoding.EncodeToString(dataBlob)
	ivB64 := base64.StdEncoding.EncodeToString(ivBlob)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": dataB64,
		"iv":   ivB64,
	})
}

func randString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		rb := int(b[i])
		if rb > maxAccept {
			for {
				rand.Read(b[i : i+1])
				rb = int(b[i])
				if rb <= maxAccept {
					break
				}
			}
		}
		b[i] = charset[rb%charsetLen]
	}
	return string(b)
}

func main() {
	flag.Parse()

	app, err := NewApp(*dbFile)
	if err != nil {
		log.Fatal(err)
	}
	defer app.Close()

	app.StartCleanup()

	mux := http.NewServeMux()

	mux.Handle("/static/", http.FileServer(http.FS(content)))

	mux.HandleFunc("/", app.serveIndex)
	mux.HandleFunc("/health", app.serveHealth)
	mux.HandleFunc("/paste", app.serveCreate)
	mux.HandleFunc("/p/", app.servePaste)

	addr := *listenAddr + ":" + *listenPort
	log.Printf("Server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, SecurityHeadersMiddleware(mux)))
}
