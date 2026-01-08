package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const (
	charset    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	charsetLen = len(charset)
	maxAccept  = 255 - (256 % charsetLen)
	ivSize     = 12 // AES-GCM IV size in bytes
)

var (
	ErrPasteNotFound = errors.New("paste not found")
	ErrPasteExpired  = errors.New("paste expired")
	validChars       [128]bool
	version          = "devel"
)

func init() {
	for _, r := range charset {
		validChars[byte(r)] = true
	}
}

//go:embed templates/index.html static/index.html static/script.js static/styles.css static/favicon.jpg static/highlight.min.js static/atom-one-light.min.css static/atom-one-dark.min.css
var content embed.FS

type PasteContent struct {
	Data    []byte
	IV      []byte
	Created time.Time
}

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

type Config struct {
	DBFile          string
	IDLength        int
	ExpDuration     time.Duration
	CleanupInterval time.Duration
	MaxSize         int64
	ListenAddr      string
	LogLevel        string
	LogFormat       string
}

func NewApp(cfg *Config) (*App, error) {
	tmpl, err := template.ParseFS(content, "templates/index.html")
	if err != nil {
		return nil, err
	}

	dbPath := cfg.DBFile
	if dbPath == ":memory:" {
		slog.Info("Using in-memory DB")
		name := randString(32)
		dbPath = fmt.Sprintf("file:%s?mode=memory&cache=shared", name)
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
		IDLength:        cfg.IDLength,
		ExpDuration:     cfg.ExpDuration,
		CleanupInterval: cfg.CleanupInterval,
		MaxSize:         cfg.MaxSize,
		AssetVersion:    version,
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
	var count int64
	if err := a.DB.QueryRow("SELECT COUNT(*) FROM pastes").Scan(&count); err != nil {
		return fmt.Errorf("database initialization failed: unable to verify paste count: %w", err)
	}
	slog.Info("database ready", "paste_count", count)
	return nil
}

func (a *App) StartBackgroundTasks(ctx context.Context) {
	go a.incrementalVacuumGoroutine(ctx)
	go a.cleanupGoroutine(ctx)
}

func (a *App) incrementalVacuumGoroutine(ctx context.Context) {
	select {
	case <-time.After(30 * time.Second):
		a.runIncrementalVacuum()
	case <-ctx.Done():
		return
	}

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.runIncrementalVacuum()
		case <-ctx.Done():
			return
		}
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
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("Cleanup rollback error", "err", err)
		}
	}()

	seconds := int(a.ExpDuration / time.Second)
	if seconds <= 0 {
		slog.Warn("Expiration duration is zero or negative – skipping cleanup", "duration", a.ExpDuration)
		return
	}
	modifier := fmt.Sprintf("-%d seconds", seconds)
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
		slog.Info("Cleaned up expired pastes", "deleted", rows)
	}
}

func (a *App) cleanupGoroutine(ctx context.Context) {
	a.runCleanup()

	ticker := time.NewTicker(a.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.runCleanup()
		case <-ctx.Done():
			return
		}
	}
}

func (a *App) Close() {
	if err := a.DB.Close(); err != nil {
		slog.Error("Failed to close database", "err", err)
	}
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
		sendText(w, "ok")
	}
}

func (a *App) serveCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request size to paste MaxSize + approx base64/JSON overhead (3/2 factor)
	r.Body = http.MaxBytesReader(w, r.Body, a.MaxSize*3/2+8192)

	var req struct {
		Data string `json:"data"`
		IV   string `json:"iv"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			slog.Warn("create request too large", "remote_addr", clientIP(r))
			http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
		} else {
			slog.Warn("invalid create request", "err", err, "remote_addr", clientIP(r))
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

	id, err := a.InsertPaste(decodedData, decodedIV)
	if err != nil {
		slog.Error("Failed to insert paste", "err", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	slog.Info("paste created", "id", id, "size_bytes", len(decodedData), "remote_addr", clientIP(r))

	sendJSON(w, map[string]string{"id": id})
}

func (a *App) InsertPaste(data, iv []byte) (string, error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()

	length := a.IDLength
	retries := 0

	for {
		id := randString(length)
		res, err := a.DB.Exec("INSERT INTO pastes (id, data, iv) VALUES (?, ?, ?)", id, data, iv)
		if err == nil {
			rows, _ := res.RowsAffected()
			if rows == 1 {
				return id, nil
			}
		}

		retries++
		if retries >= 100 {
			return "", fmt.Errorf("insert failed after %d retries", retries)
		}
		if retries%10 == 0 {
			length++
			slog.Info("id collision threshold reached", "new_length", length, "retries", retries)
		}
	}
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

	content, err := a.LoadPaste(id)
	if err != nil {
		if errors.Is(err, ErrPasteNotFound) {
			http.NotFound(w, r)
		} else if errors.Is(err, ErrPasteExpired) {
			http.Error(w, "Paste expired", http.StatusGone)
		} else {
			slog.Error("LoadPaste failed", "err", err, "id", id)
			http.Error(w, "Internal error", http.StatusInternalServerError)
		}
		return
	}

	secondsUntilExpiry := max(int(time.Until(content.Created.Add(a.ExpDuration)).Seconds()), 1)

	dataB64 := base64.StdEncoding.EncodeToString(content.Data)
	ivB64 := base64.StdEncoding.EncodeToString(content.IV)
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, immutable", secondsUntilExpiry))
	sendJSON(w, map[string]string{
		"data": dataB64,
		"iv":   ivB64,
	})
}

func (a *App) LoadPaste(id string) (*PasteContent, error) {
	var dataBlob, ivBlob []byte
	var created time.Time

	err := a.DB.QueryRow("SELECT data, iv, created FROM pastes WHERE id = ?", id).
		Scan(&dataBlob, &ivBlob, &created)
	if err == sql.ErrNoRows {
		return nil, ErrPasteNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("db query error: %w", err)
	}

	if time.Until(created.Add(a.ExpDuration)) <= 0 {
		return nil, ErrPasteExpired
	}

	return &PasteContent{
		Data:    dataBlob,
		IV:      ivBlob,
		Created: created,
	}, nil
}

func randString(length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	for i := range b {
		rb := int(b[i])
		for rb > maxAccept {
			_, _ = rand.Read(b[i : i+1])
			rb = int(b[i])
		}
		b[i] = charset[rb%charsetLen]
	}
	return string(b)
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func sendJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("JSON encode error", "err", err)
	}
}

func sendText(w http.ResponseWriter, s string) {
	if _, err := w.Write([]byte(s)); err != nil {
		slog.Debug("Text write error", "err", err)
	}
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

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := parseFlags()
	setupLogging(cfg)

	app, err := NewApp(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize app: %w", err)
	}
	defer app.Close()

	app.StartBackgroundTasks(ctx)

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      newHandler(app),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		BaseContext:  func(_ net.Listener) context.Context { return ctx },
	}

	go func() {
		slog.Info("Starting server", "version", version, "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("ListenAndServe failed", "err", err)
		}
	}()

	<-ctx.Done()
	slog.Info("Shutting down gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	return srv.Shutdown(shutdownCtx)
}

func parseFlags() *Config {
	dbFile := flag.String("db", "pastes.db", "SQLite DB file (use ':memory:' for in-mem)")
	idLength := flag.Int("idlen", 8, "Default paste ID length")
	expireDuration := flag.Duration("expire-duration", 30*24*time.Hour, "Paste expiration duration (e.g. 720h for 30 days)")
	cleanupInterval := flag.Duration("cleanup-interval", time.Hour, "Database cleanup interval")
	maxSize := flag.Int64("maxsize", 1<<20, "Maximum paste size in bytes (default 1MB)")
	listenAddr := flag.String("addr", "0.0.0.0", "Listen address")
	listenPort := flag.String("port", "8080", "Listen port")
	logLevel := flag.String("log-level", "info", "Log level")
	logFormat := flag.String("log-format", "", "Log format: text or json")

	flag.Parse()

	return &Config{
		DBFile:          *dbFile,
		IDLength:        *idLength,
		ExpDuration:     *expireDuration,
		CleanupInterval: *cleanupInterval,
		MaxSize:         *maxSize,
		ListenAddr:      *listenAddr + ":" + *listenPort,
		LogLevel:        *logLevel,
		LogFormat:       *logFormat,
	}
}

func setupLogging(cfg *Config) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	format := strings.ToLower(cfg.LogFormat)
	if format == "" {
		format = strings.ToLower(os.Getenv("LOG_FORMAT"))
	}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))
}

func main() {
	if err := run(); err != nil {
		slog.Error("Server failed", "err", err)
		os.Exit(1)
	}
}
