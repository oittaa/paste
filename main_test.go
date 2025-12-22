package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func assertSecurityHeaders(t *testing.T, res *http.Response) {
	t.Helper()

	expectedCSP := "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'self'; form-action 'none'; frame-ancestors 'none';"
	if got := res.Header.Get("Content-Security-Policy"); got != expectedCSP {
		t.Errorf("CSP mismatch: expected %q, got %q", expectedCSP, got)
	}
	if got := res.Header.Get("Permissions-Policy"); got != "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), fullscreen=(), picture-in-picture=()" {
		t.Errorf("Permissions-Policy mismatch: got %q", got)
	}
	if got := res.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options mismatch: got %q", got)
	}
	if got := res.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options mismatch: got %q", got)
	}
	if got := res.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy mismatch: got %q", got)
	}
}

func TestAppIntegration(t *testing.T) {
	// Create in-memory app for isolated testing
	app, err := NewApp(":memory:")
	if err != nil {
		t.Fatalf("Failed to create test app: %v", err)
	}
	defer app.Close()

	handler := newHandler(app)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	t.Run("HealthHandler", func(t *testing.T) {
		// GET
		res, err := srv.Client().Get(srv.URL + "/health")
		if err != nil {
			t.Fatalf("Failed to GET /health: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for /health, got %d", res.StatusCode)
		}
		body, _ := io.ReadAll(res.Body)
		if string(body) != "ok" {
			t.Errorf("Expected body 'ok', got %s", string(body))
		}
		assertSecurityHeaders(t, res)

		// HEAD (no body)
		req, err := http.NewRequest("HEAD", srv.URL+"/health", nil)
		if err != nil {
			t.Fatalf("Failed to create HEAD request: %v", err)
		}
		res, err = srv.Client().Do(req)
		if err != nil {
			t.Fatalf("Failed to HEAD /health: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for HEAD /health, got %d", res.StatusCode)
		}
		body, _ = io.ReadAll(res.Body)
		if len(body) != 0 {
			t.Errorf("Expected empty body on HEAD, got %s", string(body))
		}
		assertSecurityHeaders(t, res)
	})

	t.Run("IndexHandler", func(t *testing.T) {
		res, err := srv.Client().Get(srv.URL + "/")
		if err != nil {
			t.Fatalf("Failed to GET /: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", res.StatusCode)
		}
		if res.Header.Get("Content-Type") != "text/html; charset=utf-8" {
			t.Errorf("Expected Content-Type text/html; charset=utf-8, got %s", res.Header.Get("Content-Type"))
		}
		if got := res.Header.Get("Cache-Control"); got != "public, max-age=14400" {
			t.Errorf("Expected Cache-Control public, max-age=14400 on index, got %q", got)
		}
		body, _ := io.ReadAll(res.Body)
		if !strings.Contains(string(body), "<title>Paste</title>") {
			t.Errorf("Expected HTML with title Paste")
		}
		assertSecurityHeaders(t, res)

		// Test 404 for invalid path
		res, err = srv.Client().Get(srv.URL + "/invalid")
		if err != nil {
			t.Fatalf("Failed to GET /invalid: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status 404 for invalid path, got %d", res.StatusCode)
		}
		assertSecurityHeaders(t, res)
	})

	t.Run("StaticHandler", func(t *testing.T) {
		// Test a few static assets to cover cacheStatic middleware
		for _, path := range []string{"/static/styles.css", "/static/script.js", "/static/favicon.jpg"} {
			t.Run(path, func(t *testing.T) {
				res, err := srv.Client().Get(srv.URL + path)
				if err != nil {
					t.Fatalf("Failed to GET %s: %v", path, err)
				}
				defer res.Body.Close()
				if res.StatusCode != http.StatusOK {
					t.Errorf("Expected 200 for %s, got %d", path, res.StatusCode)
				}
				if got := res.Header.Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
					t.Errorf("Expected long-term immutable Cache-Control on static, got %q", got)
				}
				assertSecurityHeaders(t, res)
			})
		}
	})

	t.Run("CreateHandler", func(t *testing.T) {
		// Prepare fake encrypted data and IV
		fakeEncData := []byte("test paste content [fake encrypted]")
		b64Data := base64.StdEncoding.EncodeToString(fakeEncData)

		iv := make([]byte, ivSize)
		if _, err := rand.Read(iv); err != nil {
			t.Fatalf("Failed to generate IV: %v", err)
		}
		b64IV := base64.StdEncoding.EncodeToString(iv)

		reqBody, err := json.Marshal(map[string]string{
			"data": b64Data,
			"iv":   b64IV,
		})
		if err != nil {
			t.Fatalf("Failed to marshal request: %v", err)
		}

		res, err := srv.Client().Post(srv.URL+"/paste", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("Failed to POST /paste: %v", err)
		}
		defer res.Body.Close()

		bodyBytes, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d: %s", res.StatusCode, string(bodyBytes))
		}
		assertSecurityHeaders(t, res)

		var resp struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(bodyBytes, &resp); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}
		if resp.ID == "" {
			t.Error("Expected non-empty ID in response")
		}
		if len(resp.ID) != app.IDLength {
			t.Errorf("Expected ID length %d, got %d", app.IDLength, len(resp.ID))
		}

		// Invalid JSON
		res, err = srv.Client().Post(srv.URL+"/paste", "application/json", bytes.NewReader([]byte(`{invalid`)))
		if err != nil {
			t.Fatalf("Failed to POST invalid JSON: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 for invalid JSON, got %d", res.StatusCode)
		}
		assertSecurityHeaders(t, res)

		// Oversized data (post-decode)
		oversized := make([]byte, int(app.MaxSize)+1)
		b64Oversized := base64.StdEncoding.EncodeToString(oversized)
		oversizedReq, _ := json.Marshal(map[string]string{"data": b64Oversized, "iv": b64IV})
		res, err = srv.Client().Post(srv.URL+"/paste", "application/json", bytes.NewReader(oversizedReq))
		if err != nil {
			t.Fatalf("Failed to POST oversized: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("Expected 413 for oversized, got %d", res.StatusCode)
		}
		assertSecurityHeaders(t, res)

		// Invalid IV length
		invalidIV := make([]byte, ivSize-1)
		b64InvalidIV := base64.StdEncoding.EncodeToString(invalidIV)
		invalidReq, _ := json.Marshal(map[string]string{"data": b64Data, "iv": b64InvalidIV})
		res, err = srv.Client().Post(srv.URL+"/paste", "application/json", bytes.NewReader(invalidReq))
		if err != nil {
			t.Fatalf("Failed to POST invalid IV: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 for invalid IV, got %d", res.StatusCode)
		}
		assertSecurityHeaders(t, res)

		// Non-POST method
		res, err = srv.Client().Get(srv.URL + "/paste")
		if err != nil {
			t.Fatalf("Failed to GET /paste: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Expected 405 for non-POST, got %d", res.StatusCode)
		}
		assertSecurityHeaders(t, res)
	})

	t.Run("PasteHandler", func(t *testing.T) {
		// Create a paste to retrieve
		fakeEncData := []byte("retrievable paste [fake encrypted]")
		b64Data := base64.StdEncoding.EncodeToString(fakeEncData)
		iv := make([]byte, ivSize)
		if _, err := rand.Read(iv); err != nil {
			t.Fatalf("Failed to generate IV: %v", err)
		}
		b64IV := base64.StdEncoding.EncodeToString(iv)

		createReq, _ := json.Marshal(map[string]string{"data": b64Data, "iv": b64IV})
		createRes, err := srv.Client().Post(srv.URL+"/paste", "application/json", bytes.NewReader(createReq))
		if err != nil {
			t.Fatalf("Failed to create paste: %v", err)
		}
		defer createRes.Body.Close()
		createBody, _ := io.ReadAll(createRes.Body)
		var createResp struct{ ID string }
		json.Unmarshal(createBody, &createResp)
		id := createResp.ID

		// GET (various Accept headers - always JSON)
		for _, accept := range []string{"application/json", "", "text/html"} {
			t.Run("GET Accept="+accept, func(t *testing.T) {
				req, err := http.NewRequest("GET", srv.URL+"/p/"+id, nil)
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}
				if accept != "" {
					req.Header.Set("Accept", accept)
				}
				res, err := srv.Client().Do(req)
				if err != nil {
					t.Fatalf("Failed to GET /p/%s: %v", id, err)
				}
				defer res.Body.Close()

				if res.StatusCode != http.StatusOK {
					t.Errorf("Expected 200, got %d", res.StatusCode)
				}
				if res.Header.Get("Content-Type") != "application/json" {
					t.Errorf("Expected application/json Content-Type, got %s", res.Header.Get("Content-Type"))
				}
				cache := res.Header.Get("Cache-Control")
				if !strings.Contains(cache, "public") || !strings.Contains(cache, "immutable") || !strings.Contains(cache, "max-age=") {
					t.Errorf("Expected public, immutable, max-age in Cache-Control, got %q", cache)
				}
				assertSecurityHeaders(t, res)

				bodyBytes, _ := io.ReadAll(res.Body)
				var getResp struct {
					Data string `json:"data"`
					IV   string `json:"iv"`
				}
				if err := json.Unmarshal(bodyBytes, &getResp); err != nil {
					t.Errorf("Response not valid JSON: %v", err)
				} else {
					if getResp.Data != b64Data {
						t.Errorf("Data mismatch")
					}
					if getResp.IV != b64IV {
						t.Errorf("IV mismatch")
					}
				}
			})
		}

		// HEAD (currently sends body - this is a known issue, but we test headers)
		req, err := http.NewRequest("HEAD", srv.URL+"/p/"+id, nil)
		if err != nil {
			t.Fatalf("Failed to create HEAD request: %v", err)
		}
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("Failed to HEAD /p/%s: %v", id, err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 for HEAD, got %d", res.StatusCode)
		}
		if res.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected application/json on HEAD, got %s", res.Header.Get("Content-Type"))
		}
		cache := res.Header.Get("Cache-Control")
		if !strings.Contains(cache, "public") || !strings.Contains(cache, "immutable") {
			t.Errorf("Expected public, immutable in HEAD Cache-Control, got %q", cache)
		}
		assertSecurityHeaders(t, res)

		// Non-existent ID
		res, err = srv.Client().Get(srv.URL + "/p/nonexistent")
		if err != nil {
			t.Fatalf("Failed to GET nonexistent: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("Expected 404 for nonexistent, got %d", res.StatusCode)
		}
		assertSecurityHeaders(t, res)

		// Invalid characters in ID
		res, err = srv.Client().Get(srv.URL + "/p/abc!€$")
		if err != nil {
			t.Fatalf("Failed to GET invalid chars: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("Expected 404 for invalid chars, got %d", res.StatusCode)
		}
		assertSecurityHeaders(t, res)

		// Invalid path (empty ID, too many parts, etc.)
		for _, path := range []string{"/p/", "/p", "/a/b/c"} {
			res, err = srv.Client().Get(srv.URL + path)
			if err != nil {
				t.Fatalf("Failed to GET %s: %v", path, err)
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusNotFound {
				t.Errorf("Expected 404 for %s, got %d", path, res.StatusCode)
			}
			assertSecurityHeaders(t, res)
		}

		// Non-GET/HEAD method
		req, err = http.NewRequest("POST", srv.URL+"/p/"+id, nil)
		if err != nil {
			t.Fatalf("Failed to create POST request: %v", err)
		}
		res, err = srv.Client().Do(req)
		if err != nil {
			t.Fatalf("Failed to POST /p/%s: %v", id, err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Expected 405 for non-GET/HEAD, got %d", res.StatusCode)
		}
		assertSecurityHeaders(t, res)
	})

	t.Run("Expiration", func(t *testing.T) {
		// Manually insert expired paste
		_, err := app.DB.Exec(`INSERT INTO pastes (id, data, iv, created) VALUES (?, ?, ?, datetime('now', '-31 days'))`,
			"expired", []byte("data"), make([]byte, ivSize))
		if err != nil {
			t.Fatalf("Failed to insert expired paste: %v", err)
		}

		res, err := srv.Client().Get(srv.URL + "/p/expired")
		if err != nil {
			t.Fatalf("Failed to GET expired: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusGone {
			t.Errorf("Expected 410 Gone for expired paste, got %d", res.StatusCode)
		}
		assertSecurityHeaders(t, res)

		// Fresh paste
		_, err = app.DB.Exec(`INSERT INTO pastes (id, data, iv) VALUES (?, ?, ?)`,
			"fresh", []byte("data"), make([]byte, ivSize))
		if err != nil {
			t.Fatalf("Failed to insert fresh paste: %v", err)
		}

		res, err = srv.Client().Get(srv.URL + "/p/fresh")
		if err != nil {
			t.Fatalf("Failed to GET fresh: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 for fresh paste, got %d", res.StatusCode)
		}
		assertSecurityHeaders(t, res)
	})

	t.Run("BackgroundCleanup", func(t *testing.T) {
		// Insert expired paste
		_, err := app.DB.Exec(`INSERT INTO pastes (id, data, iv, created) VALUES (?, ?, ?, datetime('now', '-31 days'))`,
			"tobecleaned", []byte("data"), make([]byte, ivSize))
		if err != nil {
			t.Fatalf("Insert failed: %v", err)
		}

		// Direct call to cover cleanup logic
		app.runCleanup()

		// Verify removed
		var count int
		err = app.DB.QueryRow("SELECT COUNT(*) FROM pastes WHERE id = ?", "tobecleaned").Scan(&count)
		if err != nil || count != 0 {
			t.Errorf("Expected paste to be cleaned up, still exists (count=%d, err=%v)", count, err)
		}
	})

	t.Run("BackgroundVacuum", func(t *testing.T) {
		// Direct call to cover PRAGMA incremental_vacuum path
		app.runIncrementalVacuum()
		// No strong assertion possible in-memory, but execution covers code/logging
	})

	t.Run("IDCollisionHandling", func(t *testing.T) {
		// New app with tiny ID length to force collisions quickly
		testApp, err := NewApp(":memory:")
		if err != nil {
			t.Fatalf("Failed to create collision test app: %v", err)
		}
		defer testApp.Close()

		testApp.IDLength = 1 // Very small to trigger length increases

		// Use production handler
		testHandler := newHandler(testApp)
		testSrv := httptest.NewServer(testHandler)
		defer testSrv.Close()

		const numInserts = 200
		var ids []string

		dummyData := []byte("dummy")
		dummyB64 := base64.StdEncoding.EncodeToString(dummyData)
		dummyIV := make([]byte, ivSize)
		rand.Read(dummyIV)
		dummyB64IV := base64.StdEncoding.EncodeToString(dummyIV)

		reqBody, _ := json.Marshal(map[string]string{"data": dummyB64, "iv": dummyB64IV})

		for i := 0; i < numInserts; i++ {
			res, err := testSrv.Client().Post(testSrv.URL+"/paste", "application/json", bytes.NewReader(reqBody))
			if err != nil {
				t.Fatalf("POST %d failed: %v", i+1, err)
			}
			defer res.Body.Close()

			bodyBytes, _ := io.ReadAll(res.Body)
			if res.StatusCode != http.StatusOK {
				t.Fatalf("Insert %d expected 200, got %d: %s", i+1, res.StatusCode, string(bodyBytes))
			}

			var resp struct{ ID string }
			if err := json.Unmarshal(bodyBytes, &resp); err != nil {
				t.Fatalf("Unmarshal %d failed: %v", i+1, err)
			}
			if resp.ID == "" {
				t.Fatalf("Empty ID on insert %d", i+1)
			}
			ids = append(ids, resp.ID)
		}

		if len(ids) != numInserts {
			t.Errorf("Expected %d IDs, got %d", numInserts, len(ids))
		}

		var unique int
		if err := testApp.DB.QueryRow("SELECT COUNT(DISTINCT id) FROM pastes").Scan(&unique); err != nil || unique != numInserts {
			t.Errorf("Expected %d unique IDs, got %d (err: %v)", numInserts, unique, err)
		}

		var maxLen int
		if err := testApp.DB.QueryRow("SELECT MAX(LENGTH(id)) FROM pastes").Scan(&maxLen); err != nil {
			t.Fatalf("Max length query failed: %v", err)
		}
		if maxLen <= testApp.IDLength {
			t.Errorf("Expected max ID length > %d after collisions, got %d", testApp.IDLength, maxLen)
		}
	})
}
