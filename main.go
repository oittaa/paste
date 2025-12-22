package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	charset    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	charsetLen = len(charset)
	maxAccept  = 255 - (256 % charsetLen)
	ivSize     = 12 // AES-GCM IV size in bytes
)

var validChars [128]bool

func init() {
	for _, r := range charset {
		validChars[byte(r)] = true
	}
}

//go:embed templates/index.html static/index.html static/script.js static/styles.css static/favicon.jpg static/highlight.min.js static/atom-one-light.min.css static/atom-one-dark.min.css
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
	writeMu         sync.Mutex
	AssetVersion    string
}

func NewApp(dbPath string) (*App, error) {
	tmpl, err := template.ParseFS(content, "templates/index.html")
	if err != nil {
		return nil, err
	}

	if dbPath == ":memory:" {
		slog.Info("Using in-memory DB")
	} else {
		slog.Info("Using file DB", "path", dbPath)
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

	exePath, err := os.Executable()
	if err != nil {
		slog.Warn("Failed to get executable path", "err", err)
	} else {
		f, err := os.Open(exePath)
		if err != nil {
			slog.Warn("Failed to open executable for hashing", "err", err)
		} else {
			defer f.Close()
			h := sha256.New()
			if _, err := io.Copy(h, f); err != nil {
				slog.Warn("Failed to hash binary", "err", err)
			} else {
				fullHash := h.Sum(nil)
				app.AssetVersion = base64.RawURLEncoding.EncodeToString(fullHash[:9])
				slog.Debug("Computed asset version from binary hash", "version", app.AssetVersion)
			}
		}
	}
	if app.AssetVersion == "" {
		app.AssetVersion = "devel"
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
		slog.Warn("Failed to create index", "err", err)
	}
	_, err = a.DB.Exec("PRAGMA journal_mode=WAL")
	if err != nil {
		return err
	}
	_, err = a.DB.Exec("PRAGMA synchronous=NORMAL")
	if err != nil {
		return err
	}
	_, err = a.DB.Exec("PRAGMA busy_timeout=5000")
	if err != nil {
		return err
	}
	_, err = a.DB.Exec("PRAGMA auto_vacuum = INCREMENTAL")
	if err != nil {
		slog.Warn("Failed to enable incremental auto_vacuum", "err", err)
	}
	return nil
}

func (a *App) StartBackgroundTasks() {
	go a.incrementalVacuumGoroutine()
	go a.cleanupGoroutine()
}

func (a *App) incrementalVacuumGoroutine() {
	time.Sleep(30 * time.Second)
	a.runIncrementalVacuum()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		a.runIncrementalVacuum()
	}
}

func (a *App) runIncrementalVacuum() {
	_, err := a.DB.Exec("PRAGMA incremental_vacuum")
	if err != nil {
		slog.Error("Incremental vacuum failed", "err", err)
		return
	}
	slog.Info("Incremental vacuum completed")
}

func (a *App) runCleanup() {
	tx, err := a.DB.Begin()
	if err != nil {
		slog.Error("Cleanup tx begin error", "err", err)
		return
	}
	defer tx.Rollback()

	hours := int(a.ExpDuration.Hours())
	modifier := fmt.Sprintf("-%d hours", hours)
	res, err := tx.Exec("DELETE FROM pastes WHERE created < datetime('now', ?)", modifier)
	if err != nil {
		slog.Error("Cleanup delete error", "err", err)
		return
	}
	rows, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		slog.Error("Cleanup commit error", "err", err)
		return
	}
	if rows > 0 {
		slog.Info("Cleaned up expired pastes", "count", rows)
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
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), fullscreen=(), picture-in-picture=()")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		next.ServeHTTP(w, r)
	})
}

// Handlers as methods on *App

func (a *App) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	a.serveHTML(w, r)
}

func (a *App) serveHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=14400")

	if r.Method == http.MethodHead {
		return
	}

	type templateData struct {
		AssetVersion string
	}
	if err := a.Tmpl.Execute(w, templateData{AssetVersion: a.AssetVersion}); err != nil {
		slog.Error("Template execute error", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (a *App) serveHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := a.DB.Ping(); err != nil {
		slog.Error("Health check failed: DB ping error", "err", err)
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

	a.writeMu.Lock()
	defer a.writeMu.Unlock()

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
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
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
		if ch >= 128 || !validChars[byte(ch)] {
			http.NotFound(w, r)
			return
		}
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
			slog.Error("Database query error", "err", err, "id", id)
			http.Error(w, "Internal error", http.StatusInternalServerError)
		}
		return
	}

	expiresAt := created.Add(a.ExpDuration)
	secondsUntilExpiry := time.Until(expiresAt).Seconds()

	if secondsUntilExpiry <= 0 {
		http.Error(w, "Paste expired", http.StatusGone)
		return
	}

	dataB64 := base64.StdEncoding.EncodeToString(dataBlob)
	ivB64 := base64.StdEncoding.EncodeToString(ivBlob)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, immutable", int(secondsUntilExpiry)))
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

func newHandler(app *App) http.Handler {
	mux := http.NewServeMux()

	// Static files with long-term caching (immutable)
	mux.Handle("/static/", cacheStatic(http.FileServer(http.FS(content))))

	// Routes
	mux.HandleFunc("/", app.serveIndex)
	mux.HandleFunc("/health", app.serveHealth)
	mux.HandleFunc("/paste", app.serveCreate)
	mux.HandleFunc("/p/", app.servePaste)

	// Apply security headers to everything
	return SecurityHeadersMiddleware(mux)
}

func main() {
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	app, err := NewApp(*dbFile)
	if err != nil {
		slog.Error("Failed to initialize app", "err", err)
		os.Exit(1)
	}
	defer app.Close()

	app.StartBackgroundTasks()

	addr := *listenAddr + ":" + *listenPort
	slog.Info("Server listening", "addr", addr)
	if err := http.ListenAndServe(addr, newHandler(app)); err != nil {
		slog.Error("Server failed", "err", err)
		os.Exit(1)
	}
}
