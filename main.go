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
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const (
	ivSize = 12 // AES-GCM IV size in bytes
)

var (
	ErrPasteNotFound = errors.New("paste not found")
	ErrPasteExpired  = errors.New("paste expired")
	version          = "devel"
)

//go:embed templates/index.html static/index.html static/script.js static/styles.css static/favicon.jpg static/highlight.min.js static/atom-one-light.min.css static/atom-one-dark.min.css static/screenshot.png
var content embed.FS

type PasteContent struct {
	Data    []byte
	IV      []byte
	Created time.Time
}

type App struct {
	DB           *sql.DB
	Tmpl         *template.Template
	Config       *Config
	AssetVersion string
	validChars   [128]bool
}

func DefaultConfig() *Config {
	return &Config{
		DBFile:          "pastes.db",
		IDLength:        8,
		ExpDuration:     30 * 24 * time.Hour,
		CleanupInterval: time.Hour,
		MaxSize:         1 << 20,
		ListenAddr:      "0.0.0.0:8080",
		LogLevel:        "info",
		LogFormat:       "",
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    10 * time.Second,
		IdleTimeout:     120 * time.Second,
		ShutdownTimeout: 15 * time.Second,
		VacuumDelay:     30 * time.Second,
		VacuumInterval:  24 * time.Hour,
		BusyTimeout:     5000,
		IndexCache:      "public, max-age=14400",
		StaticCache:     "public, max-age=31536000, immutable",
		Charset:         "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	}
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
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	VacuumDelay     time.Duration
	VacuumInterval  time.Duration
	BusyTimeout     int
	IndexCache      string
	StaticCache     string
	Charset         string
	URL             string
}

func NewApp(cfg *Config) (*App, error) {
	tmpl, err := template.ParseFS(content, "templates/index.html")
	if err != nil {
		return nil, err
	}

	dbPath := cfg.DBFile
	if dbPath == ":memory:" {
		slog.Info("Using in-memory DB")
		name := randString(32, cfg.Charset)
		dbPath = fmt.Sprintf("file:%s?mode=memory&cache=shared", name)
	} else {
		slog.Info("Using file DB", "path", dbPath)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	app := &App{
		DB:           db,
		Tmpl:         tmpl,
		Config:       cfg,
		AssetVersion: version,
	}

	for _, r := range cfg.Charset {
		if r < 128 {
			app.validChars[byte(r)] = true
		}
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
	_, err = a.DB.Exec(fmt.Sprintf("PRAGMA busy_timeout=%d", a.Config.BusyTimeout))
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
	case <-time.After(a.Config.VacuumDelay):
		a.runIncrementalVacuum(ctx)
	case <-ctx.Done():
		return
	}

	ticker := time.NewTicker(a.Config.VacuumInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.runIncrementalVacuum(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (a *App) runIncrementalVacuum(ctx context.Context) {
	if _, err := a.DB.ExecContext(ctx, "PRAGMA incremental_vacuum"); err != nil {
		slog.Error("Incremental vacuum failed", "err", err)
	}
	slog.Info("Incremental vacuum completed")
}

func (a *App) runCleanup(ctx context.Context) {
	seconds := int(a.Config.ExpDuration.Seconds())
	if seconds <= 0 {
		return
	}
	modifier := fmt.Sprintf("-%d seconds", seconds)
	res, err := a.DB.ExecContext(ctx, "DELETE FROM pastes WHERE created < datetime('now', ?)", modifier)
	if err != nil {
		slog.Error("Database cleanup failed", "err", err)
		return
	}
	count, _ := res.RowsAffected()
	if count > 0 {
		slog.Info("Expired pastes cleaned up", "count", count)
	}
}

func (a *App) cleanupGoroutine(ctx context.Context) {
	a.runCleanup(ctx)

	ticker := time.NewTicker(a.Config.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.runCleanup(ctx)
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

func (a *App) cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", a.Config.StaticCache)
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
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", a.Config.IndexCache)

	if r.Method == http.MethodHead {
		return
	}

	type templateData struct {
		AssetVersion string
		URL          string
	}
	if err := a.Tmpl.Execute(w, templateData{
		AssetVersion: a.AssetVersion,
		URL:          a.Config.URL,
	}); err != nil {
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
	r.Body = http.MaxBytesReader(w, r.Body, a.Config.MaxSize*3/2+8192)

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

	if int64(len(req.Data)) > a.Config.MaxSize*2 {
		http.Error(w, "Payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	decodedData, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		http.Error(w, "Invalid data encoding", http.StatusBadRequest)
		return
	}
	if int64(len(decodedData)) > a.Config.MaxSize {
		http.Error(w, "Oversized data", http.StatusRequestEntityTooLarge)
		return
	}

	decodedIV, err := base64.StdEncoding.DecodeString(req.IV)
	if err != nil || len(decodedIV) != ivSize {
		http.Error(w, "Invalid IV", http.StatusBadRequest)
		return
	}

	id, err := a.InsertPaste(r.Context(), decodedData, decodedIV)
	if err != nil {
		slog.Error("Failed to insert paste", "err", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	slog.Info("paste created", "id", id, "size_bytes", len(decodedData), "remote_addr", clientIP(r))

	sendJSON(w, map[string]string{"id": id})
}

func (a *App) InsertPaste(ctx context.Context, data, iv []byte) (string, error) {
	for retries := range 10 {
		length := a.Config.IDLength + retries
		id := randString(length, a.Config.Charset)
		res, err := a.DB.ExecContext(ctx, "INSERT OR IGNORE INTO pastes (id, data, iv) VALUES (?, ?, ?)", id, data, iv)
		if err != nil {
			return "", fmt.Errorf("insert error: %w", err)
		}
		rows, err := res.RowsAffected()
		if err != nil {
			return "", fmt.Errorf("rows affected error: %w", err)
		}
		if rows == 1 {
			return id, nil
		}
		slog.Warn("id collision", "length", length, "retries", retries+1)
	}
	return "", fmt.Errorf("insert failed after 10 attempts")
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
		if ch >= 128 || !a.validChars[byte(ch)] {
			http.NotFound(w, r)
			return
		}
	}

	content, err := a.LoadPaste(r.Context(), id)
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

	secondsUntilExpiry := max(int(time.Until(content.Created.Add(a.Config.ExpDuration)).Seconds()), 1)

	dataB64 := base64.StdEncoding.EncodeToString(content.Data)
	ivB64 := base64.StdEncoding.EncodeToString(content.IV)
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, immutable", secondsUntilExpiry))
	sendJSON(w, map[string]string{
		"data": dataB64,
		"iv":   ivB64,
	})
}

func (a *App) LoadPaste(ctx context.Context, id string) (*PasteContent, error) {
	var dataBlob, ivBlob []byte
	var created time.Time

	err := a.DB.QueryRowContext(ctx, "SELECT data, iv, created FROM pastes WHERE id = ?", id).
		Scan(&dataBlob, &ivBlob, &created)
	if err == sql.ErrNoRows {
		return nil, ErrPasteNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("db query error: %w", err)
	}

	if time.Until(created.Add(a.Config.ExpDuration)) <= 0 {
		return nil, ErrPasteExpired
	}

	return &PasteContent{
		Data:    dataBlob,
		IV:      ivBlob,
		Created: created,
	}, nil
}

func randString(length int, charset string) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	cLen := len(charset)
	maxAcc := 255 - (256 % cLen)
	for i := range b {
		rb := int(b[i])
		for rb > maxAcc {
			_, _ = rand.Read(b[i : i+1])
			rb = int(b[i])
		}
		b[i] = charset[rb%cLen]
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
	mux.Handle("/static/", app.cacheStatic(http.FileServer(http.FS(content))))

	// Routes
	mux.HandleFunc("/", app.serveIndex)
	mux.HandleFunc("/health", app.serveHealth)
	mux.HandleFunc("/paste", app.serveCreate)
	mux.HandleFunc("/p/", app.servePaste)

	// Apply security headers to everything
	return SecurityHeadersMiddleware(mux)
}

func run(ctx context.Context, cfg *Config) error {
	app, err := NewApp(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize app: %w", err)
	}
	defer app.Close()

	app.StartBackgroundTasks(ctx)

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      newHandler(app),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
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

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
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
	url := flag.String("url", "", "Public URL (e.g. https://paste.example.com)")
	logLevel := flag.String("log-level", "info", "Log level")
	logFormat := flag.String("log-format", "", "Log format: text or json (default: text)")

	flag.Parse()

	cfg := DefaultConfig()
	cfg.DBFile = *dbFile
	cfg.IDLength = *idLength
	cfg.ExpDuration = *expireDuration
	cfg.CleanupInterval = *cleanupInterval
	cfg.MaxSize = *maxSize
	cfg.ListenAddr = *listenAddr + ":" + *listenPort

	cfg.URL = *url
	if cfg.URL == "" {
		cfg.URL = os.Getenv("URL")
	}
	cfg.LogLevel = *logLevel
	cfg.LogFormat = *logFormat

	return cfg
}

func setupLogging(cfg *Config) {
	var level slog.Level
	err := level.UnmarshalText([]byte(cfg.LogLevel))
	if err != nil {
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

	if err != nil {
		slog.Warn("invalid log level, defaulting to info", "level", cfg.LogLevel, "err", err)
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := parseFlags()
	setupLogging(cfg)

	if err := run(ctx, cfg); err != nil {
		slog.Error("Server failed", "err", err)
		os.Exit(1)
	}
}
