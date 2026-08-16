package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// testApp wraps the App and its test server
type testApp struct {
	*App
	srv *httptest.Server
}

// newTestApp creates a new test instance with an in-memory database by default
func newTestApp(t *testing.T, cfg *Config) *testApp {
	t.Helper()
	// Always favor :memory: for tests unless a specific file is requested
	if cfg.DBFile == "pastes.db" || cfg.DBFile == "" {
		cfg.DBFile = ":memory:"
	}
	app, err := NewApp(cfg)
	if err != nil {
		t.Fatalf("Failed to create test app: %v", err)
	}
	srv := httptest.NewServer(newHandler(app))
	ta := &testApp{App: app, srv: srv}
	t.Cleanup(ta.Close)
	return ta
}

func (ta *testApp) Close() {
	ta.srv.Close()
	ta.App.Close()
}

// do performs an HTTP request against the test server
func (ta *testApp) do(t *testing.T, method, path string, body interface{}, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			bodyReader = strings.NewReader(v)
		default:
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("Failed to marshal body: %v", err)
			}
			bodyReader = bytes.NewReader(b)
		}
	}

	req, err := http.NewRequest(method, ta.srv.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	if body != nil && (headers == nil || headers["Content-Type"] == "") {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	res, err := ta.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = res.Body.Close() }()

	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	return res, respBody
}

func assertSecurityHeaders(t *testing.T, res *http.Response) {
	t.Helper()
	expectedCSP := "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'self'; form-action 'none'; frame-ancestors 'none';"
	headers := map[string]string{
		"Content-Security-Policy": expectedCSP,
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
	}
	for k, v := range headers {
		if got := res.Header.Get(k); got != v {
			t.Errorf("Header %s mismatch: expected %q, got %q", k, v, got)
		}
	}
}

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

func TestNewAppErrors(t *testing.T) {
	t.Run("InvalidDB", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DBFile = "/nonexistent/path"
		_, err := NewApp(cfg)
		if err == nil {
			t.Error("expected error for invalid DB path")
		}
	})
	t.Run("InvalidConfig", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.IDLength = 0
		_, err := NewApp(cfg)
		if err == nil {
			t.Error("expected error for invalid config")
		}
	})
}

func TestConfigValidate(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("DefaultConfig is invalid: %v", err)
	}

	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"Nil", nil, "config is nil"},
		{"EmptyDB", func(c *Config) { c.DBFile = "" }, "db path"},
		{"IDLenZero", func(c *Config) { c.IDLength = 0 }, "id length"},
		{"IDLenTooLong", func(c *Config) { c.IDLength = maxIDLength + 1 }, "id length"},
		{"ExpireZero", func(c *Config) { c.ExpDuration = 0 }, "expire duration"},
		{"CleanupZero", func(c *Config) { c.CleanupInterval = 0 }, "cleanup interval"},
		{"MaxSizeZero", func(c *Config) { c.MaxSize = 0 }, "max size"},
		{"MaxSizeOverflow", func(c *Config) { c.MaxSize = math.MaxInt64 }, "max size"},
		{"ReadTimeoutZero", func(c *Config) { c.ReadTimeout = 0 }, "timeouts"},
		{"ShutdownTimeoutZero", func(c *Config) { c.ShutdownTimeout = 0 }, "shutdown timeout"},
		{"VacuumDelayNeg", func(c *Config) { c.VacuumDelay = -1 }, "vacuum delay"},
		{"VacuumIntervalZero", func(c *Config) { c.VacuumInterval = 0 }, "vacuum interval"},
		{"BusyTimeoutNeg", func(c *Config) { c.BusyTimeout = -1 }, "busy timeout"},
		{"RateLimitNeg", func(c *Config) { c.RateLimit = -1 }, "rate limit"},
		{"RateWindowNeg", func(c *Config) { c.RateWindow = -1 }, "rate window"},
		{"RateWindowZeroWithLimit", func(c *Config) { c.RateLimit = 10; c.RateWindow = 0 }, "rate window"},
		{"MaxPastesNeg", func(c *Config) { c.MaxPastes = -1 }, "max pastes"},
		{"MaxStorageNeg", func(c *Config) { c.MaxStorage = -1 }, "max storage"},
		{"CharsetEmpty", func(c *Config) { c.Charset = "" }, "charset"},
		{"CharsetOneChar", func(c *Config) { c.Charset = "A" }, "charset"},
		{"CharsetSlash", func(c *Config) { c.Charset = "AB/" }, "charset"},
		{"CharsetColon", func(c *Config) { c.Charset = "AB:" }, "charset"},
		{"ListenBad", func(c *Config) { c.ListenAddr = "not-an-addr" }, "listen address"},
		{"ListenPortBad", func(c *Config) { c.ListenAddr = "127.0.0.1:99999" }, "listen port"},
		{"URLBad", func(c *Config) { c.URL = "javascript:alert(1)" }, "url"},
		{"LogLevelBad", func(c *Config) { c.LogLevel = "nope" }, "log level"},
		{"LogFormatBad", func(c *Config) { c.LogFormat = "xml" }, "log format"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.mut == nil {
				err = (*Config)(nil).Validate()
			} else {
				cfg := DefaultConfig()
				tc.mut(cfg)
				err = cfg.Validate()
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}

	t.Run("IDLenMaxOK", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.IDLength = maxIDLength
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("ListenPortZeroOK", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.ListenAddr = "127.0.0.1:0"
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("HTTPSURLOK", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.URL = "https://paste.example.com"
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAppIntegration(t *testing.T) {
	ta := newTestApp(t, DefaultConfig())

	t.Run("Endpoints", func(t *testing.T) {
		tests := []struct {
			name     string
			method   string
			path     string
			expected string // substring
			status   int
		}{
			{"Health", "GET", "/health", "ok", 200},
			{"Index", "GET", "/", "<title>Paste</title>", 200},
			{"IndexHEAD", "HEAD", "/", "", 200},
			{"IndexPOST", "POST", "/", "Method not allowed", 405},
			{"IndexNotFound", "GET", "/any", "404 page not found", 404},
			{"StaticCSS", "GET", "/static/styles.css", "body {", 200},
			{"NotFound", "GET", "/p/invalid/too/many/parts", "404 page not found", 404},
			{"PasteNotFound", "GET", "/p/none", "404 page not found", 404},
			{"PasteInvalidChar", "GET", "/p/abc!", "404 page not found", 404},
			{"PasteNonASCII", "GET", "/p/abc\x80", "404 page not found", 404},
			{"MethodNotAllowed", "POST", "/health", "Method not allowed", 405},
			{"PasteMethodNotAllowed", "POST", "/p/any", "Method not allowed", 405},
			{"CreateMethodNotAllowed", "GET", "/paste", "Method not allowed", 405},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				res, body := ta.do(t, tt.method, tt.path, nil, nil)
				if res.StatusCode != tt.status {
					t.Errorf("expected %d, got %d", tt.status, res.StatusCode)
				}
				if !strings.Contains(string(body), tt.expected) {
					t.Errorf("body doesn't contain %q", tt.expected)
				}
				assertSecurityHeaders(t, res)

				if tt.method == "GET" && tt.status == 200 {
					resHead, bodyHead := ta.do(t, "HEAD", tt.path, nil, nil)
					if resHead.StatusCode != 200 {
						t.Errorf("HEAD expected 200, got %d", resHead.StatusCode)
					}
					if len(bodyHead) != 0 {
						t.Errorf("HEAD expected empty body, got %d bytes", len(bodyHead))
					}
				}
			})
		}
	})

	t.Run("CreateAndRetrieve", func(t *testing.T) {
		validIV := base64.StdEncoding.EncodeToString(make([]byte, ivSize))
		validData := base64.StdEncoding.EncodeToString([]byte("test data"))

		res, body := ta.do(t, "POST", "/paste", map[string]string{"data": validData, "iv": validIV}, nil)
		if res.StatusCode != 200 {
			t.Fatalf("Create failed: %d %s", res.StatusCode, string(body))
		}
		var resp struct{ ID string }
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}
		id := resp.ID

		res, body = ta.do(t, "GET", "/p/"+id, nil, nil)
		if res.StatusCode != 200 {
			t.Errorf("Retrieve failed: %d", res.StatusCode)
		}
		var getResp struct{ Data string }
		if err := json.Unmarshal(body, &getResp); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}
		if getResp.Data != validData {
			t.Errorf("Data mismatch: expected %q, got %q", validData, getResp.Data)
		}
		assertSecurityHeaders(t, res)
	})

	t.Run("CreateErrors", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.MaxSize = 10
		smallApp := newTestApp(t, cfg)

		cases := []struct {
			name   string
			body   interface{}
			status int
			msg    string
		}{
			{"InvalidJSON", "{invalid", 400, "Invalid JSON"},
			{"PayloadTooLarge", map[string]string{"data": strings.Repeat("A", 100)}, 413, "Payload too large"},
			{"OversizedData", map[string]string{"data": base64.StdEncoding.EncodeToString(make([]byte, 11))}, 413, "Oversized data"},
			{"RequestTooLarge", map[string]string{"data": strings.Repeat("A", 10000)}, 413, "Request too large"},
			{"InvalidBase64", map[string]string{"data": "!!!"}, 400, "Invalid data encoding"},
			{"InvalidIV", map[string]string{"data": "YQ==", "iv": "YQ=="}, 400, "Invalid IV"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				res, body := smallApp.do(t, "POST", "/paste", tc.body, nil)
				if res.StatusCode != tc.status {
					t.Errorf("expected %d, got %d", tc.status, res.StatusCode)
				}
				if !strings.Contains(string(body), tc.msg) {
					t.Errorf("expected message %q, got %q", tc.msg, string(body))
				}
			})
		}
	})

	t.Run("Expiration", func(t *testing.T) {
		if _, err := ta.DB.Exec(`INSERT INTO pastes (id, data, iv, created) VALUES (?, ?, ?, datetime('now', '-31 days'))`,
			"expired", []byte("data"), make([]byte, ivSize)); err != nil {
			t.Fatalf("Failed to insert expired paste: %v", err)
		}

		res, _ := ta.do(t, "GET", "/p/expired", nil, nil)
		if res.StatusCode != http.StatusGone {
			t.Errorf("expected 410, got %d", res.StatusCode)
		}
	})

	t.Run("BackgroundTasks", func(t *testing.T) {
		if _, err := ta.DB.Exec(`INSERT INTO pastes (id, data, iv, created) VALUES (?, ?, ?, datetime('now', '-31 days'))`,
			"cleanup", []byte("data"), make([]byte, ivSize)); err != nil {
			t.Fatalf("Failed to insert cleanup paste: %v", err)
		}
		ta.runCleanup(t.Context())
		var count int
		if err := ta.DB.QueryRow("SELECT COUNT(*) FROM pastes WHERE id = ?", "cleanup").Scan(&count); err != nil {
			t.Fatalf("Failed to scan count: %v", err)
		}
		if count != 0 {
			t.Error("expected paste to be cleaned up")
		}
		ta.runIncrementalVacuum(t.Context())

		// Test vacuum with small table
		if _, err := ta.DB.Exec("DELETE FROM pastes"); err != nil {
			t.Fatalf("Failed to delete pastes: %v", err)
		}
		ta.runIncrementalVacuum(t.Context())
	})

	t.Run("IDCollision", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.IDLength = 1
		collideApp := newTestApp(t, cfg)

		req := map[string]string{"data": "YQ==", "iv": base64.StdEncoding.EncodeToString(make([]byte, ivSize))}
		for i := range 100 {
			res, _ := collideApp.do(t, "POST", "/paste", req, nil)
			if res.StatusCode != 200 {
				t.Fatalf("Collision insert failed at %d", i)
			}
		}
		var maxLen int
		if err := collideApp.DB.QueryRow("SELECT MAX(LENGTH(id)) FROM pastes").Scan(&maxLen); err != nil {
			t.Fatalf("Failed to scan max length: %v", err)
		}
		if maxLen <= 1 {
			t.Errorf("expected collision growth, got max length %d", maxLen)
		}
	})
}

func TestConcurrentReads(t *testing.T) {
	ta := newTestApp(t, DefaultConfig())
	validIV := base64.StdEncoding.EncodeToString(make([]byte, ivSize))
	validData := base64.StdEncoding.EncodeToString([]byte("concurrent data"))

	_, body := ta.do(t, "POST", "/paste", map[string]string{"data": validData, "iv": validIV}, nil)
	var resp struct{ ID string }
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	id := resp.ID

	const concurrency = 100
	var wg sync.WaitGroup
	var failed atomic.Int32

	for range concurrency {
		wg.Go(func() {
			res, data := ta.do(t, "GET", "/p/"+id, nil, nil)
			if res.StatusCode != 200 {
				failed.Add(1)
				return
			}
			var getResp struct{ Data string }
			if err := json.Unmarshal(data, &getResp); err != nil {
				failed.Add(1)
				return
			}
			if getResp.Data != validData {
				failed.Add(1)
			}
		})
	}
	wg.Wait()
	if failed.Load() > 0 {
		t.Errorf("Concurrent reads failed: %d/%d", failed.Load(), concurrency)
	}
}

func TestConcurrentWrites(t *testing.T) {
	ta := newTestApp(t, DefaultConfig())

	const concurrency = 100
	var wg sync.WaitGroup
	var successful atomic.Int32

	validIV := base64.StdEncoding.EncodeToString(make([]byte, ivSize))
	validData := base64.StdEncoding.EncodeToString([]byte("concurrent write data"))

	for range concurrency {
		wg.Go(func() {
			res, _ := ta.do(t, "POST", "/paste", map[string]string{"data": validData, "iv": validIV}, nil)
			if res.StatusCode == 200 {
				successful.Add(1)
			}
		})
	}
	wg.Wait()

	if successful.Load() != concurrency {
		t.Errorf("Concurrent writes failed: only %d/%d succeeded", successful.Load(), concurrency)
	}

	var count int
	if err := ta.DB.QueryRow("SELECT COUNT(*) FROM pastes").Scan(&count); err != nil {
		t.Fatalf("Failed to count pastes: %v", err)
	}
	if count != int(concurrency) {
		t.Errorf("Database count mismatch: expected %d, got %d", concurrency, count)
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remote     string
		trustProxy bool
		expected   string
	}{
		{"CFTrusted", map[string]string{"CF-Connecting-IP": "1.1.1.1"}, "2.2.2.2:123", true, "1.1.1.1"},
		{"XFFTrusted", map[string]string{"X-Forwarded-For": "3.3.3.3, 4.4.4.4"}, "2.2.2.2:123", true, "3.3.3.3"},
		{"CFUntrusted", map[string]string{"CF-Connecting-IP": "1.1.1.1"}, "2.2.2.2:123", false, "2.2.2.2"},
		{"XFFUntrusted", map[string]string{"X-Forwarded-For": "3.3.3.3, 4.4.4.4"}, "2.2.2.2:123", false, "2.2.2.2"},
		{"Remote", map[string]string{}, "5.5.5.5:123", false, "5.5.5.5"},
		{"IPv6", map[string]string{}, "[2001:db8::1]:123", false, "2001:db8::1"},
		{"Invalid", map[string]string{}, "invalid", false, "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			req.RemoteAddr = tt.remote
			if got := clientIP(req, tt.trustProxy); got != tt.expected {
				t.Errorf("got %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestParseFlags(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	tmpFile, _ := os.CreateTemp("", "test.db")
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	os.Args = []string{"cmd", "-port", "9999", "-db", tmpPath}
	cfg := parseFlags()
	if cfg.ListenAddr != "0.0.0.0:9999" || cfg.DBFile != tmpPath {
		t.Errorf("cfg mismatch: %+v", cfg)
	}
	if cfg.RateLimit != 60 || cfg.MaxPastes != 100000 || cfg.MaxStorage != 1<<30 || cfg.TrustProxy {
		t.Errorf("production limit defaults mismatch: %+v", cfg)
	}
}

func TestHandlersDatabaseDown(t *testing.T) {
	ta := newTestApp(t, DefaultConfig())
	if err := ta.DB.Close(); err != nil {
		t.Fatalf("Failed to close DB: %v", err)
	}

	tests := []struct {
		name   string
		method string
		path   string
		status int
	}{
		{"Health", "GET", "/health", 503},
		{"Create", "POST", "/paste", 500},
		{"Get", "GET", "/p/any", 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := map[string]string{"data": "YmFzZTY0", "iv": base64.StdEncoding.EncodeToString(make([]byte, ivSize))}
			res, _ := ta.do(t, tt.method, tt.path, body, nil)
			if res.StatusCode != tt.status {
				t.Errorf("%s: expected %d, got %d", tt.name, tt.status, res.StatusCode)
			}
		})
	}
}

func TestAppCloseRobustness(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	app := &App{DB: db}
	app.Close()
	app.Close()
}

func TestSendHelpersError(t *testing.T) {
	t.Run("sendJSONError", func(t *testing.T) {
		rr := httptest.NewRecorder()
		sendJSON(rr, map[string]interface{}{"f": func() {}})
	})
	t.Run("sendTextError", func(t *testing.T) {
		rr := httptest.NewRecorder()
		sendText(rr, "ok")
		// Force write error
		sendText(&failingWriter{}, "fail")
	})
}

type failingWriter struct{ http.ResponseWriter }

func (f *failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (f *failingWriter) Header() http.Header       { return http.Header{} }
func (f *failingWriter) WriteHeader(int)           {}

func TestSetupLogging(t *testing.T) {
	setupLogging(&Config{LogLevel: "debug", LogFormat: "json"})
	setupLogging(&Config{LogLevel: "warn", LogFormat: "text"})
	setupLogging(&Config{LogLevel: "error", LogFormat: ""})
	setupLogging(&Config{LogLevel: "invalid-level", LogFormat: "text"})
}

func TestRun(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DBFile = ":memory:"
	cfg.ListenAddr = "127.0.0.1:0"
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := run(ctx, cfg); err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("run() failed: %v", err)
	}
}

func TestRunListenError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	cfg := DefaultConfig()
	cfg.DBFile = ":memory:"
	cfg.ListenAddr = ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := run(ctx, cfg); err == nil {
		t.Fatal("expected listen error")
	}
}

func validPasteBody() map[string]string {
	return map[string]string{
		"data": base64.StdEncoding.EncodeToString([]byte("test data")),
		"iv":   base64.StdEncoding.EncodeToString(make([]byte, ivSize)),
	}
}

func TestRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RateLimit = 2
	cfg.RateWindow = time.Minute
	ta := newTestApp(t, cfg)

	for i := range 2 {
		res, body := ta.do(t, "POST", "/paste", validPasteBody(), nil)
		if res.StatusCode != 200 {
			t.Fatalf("create %d: expected 200, got %d %s", i, res.StatusCode, body)
		}
	}
	res, body := ta.do(t, "POST", "/paste", validPasteBody(), nil)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "Rate limit exceeded") {
		t.Errorf("unexpected body %q", body)
	}
	if res.Header.Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
}

func TestStorageCapMaxPastes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPastes = 1
	ta := newTestApp(t, cfg)

	res, body := ta.do(t, "POST", "/paste", validPasteBody(), nil)
	if res.StatusCode != 200 {
		t.Fatalf("first create: expected 200, got %d %s", res.StatusCode, body)
	}
	res, body = ta.do(t, "POST", "/paste", validPasteBody(), nil)
	if res.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("expected 507, got %d %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "Storage full") {
		t.Errorf("unexpected body %q", body)
	}
}

func TestStorageCapMaxBytes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxStorage = 5
	ta := newTestApp(t, cfg)

	res, body := ta.do(t, "POST", "/paste", validPasteBody(), nil)
	if res.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("expected 507, got %d %s", res.StatusCode, body)
	}
}

func TestAutoVacuumIncremental(t *testing.T) {
	ta := newTestApp(t, DefaultConfig())
	var mode int
	if err := ta.DB.QueryRow("PRAGMA auto_vacuum").Scan(&mode); err != nil {
		t.Fatalf("PRAGMA auto_vacuum: %v", err)
	}
	if mode != autoVacuumIncremental {
		t.Fatalf("auto_vacuum=%d, want %d (incremental)", mode, autoVacuumIncremental)
	}
}

func TestAutoVacuumMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE pastes (
		id TEXT PRIMARY KEY,
		data BLOB NOT NULL,
		iv BLOB NOT NULL,
		created DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	var mode int
	if err := db.QueryRow("PRAGMA auto_vacuum").Scan(&mode); err != nil {
		t.Fatalf("PRAGMA auto_vacuum: %v", err)
	}
	if mode == autoVacuumIncremental {
		t.Fatal("legacy db already uses incremental auto_vacuum")
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	cfg := DefaultConfig()
	cfg.DBFile = path
	app, err := NewApp(cfg)
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	t.Cleanup(app.Close)
	if err := app.DB.QueryRow("PRAGMA auto_vacuum").Scan(&mode); err != nil {
		t.Fatalf("PRAGMA auto_vacuum after migrate: %v", err)
	}
	if mode != autoVacuumIncremental {
		t.Fatalf("auto_vacuum=%d, want %d after migration", mode, autoVacuumIncremental)
	}
}
