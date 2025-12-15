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

func TestAppIntegration(t *testing.T) {
	// Create in-memory app for isolated testing
	app, err := NewApp(":memory:")
	if err != nil {
		t.Fatalf("Failed to create test app: %v", err)
	}
	defer app.Close()

	// Do not start cleanup goroutine for tests

	// Set up mux with handlers (new method-based style)
	mux := http.NewServeMux()
	mux.Handle("/static/", http.FileServer(http.FS(content)))
	mux.HandleFunc("/", app.serveIndex)
	mux.HandleFunc("/health", app.serveHealth)
	mux.HandleFunc("/paste", app.serveCreate)
	mux.HandleFunc("/p/", app.servePaste)

	// Create test server
	srv := httptest.NewServer(mux)
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
		body, _ := io.ReadAll(res.Body)
		if !strings.Contains(string(body), "<title>Paste</title>") {
			t.Errorf("Expected HTML with title Paste")
		}

		// Test 404 for invalid path
		res, err = srv.Client().Get(srv.URL + "/invalid")
		if err != nil {
			t.Fatalf("Failed to GET /invalid: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status 404 for invalid path, got %d", res.StatusCode)
		}
	})

	t.Run("CreateHandler", func(t *testing.T) {
		// Prepare fake encrypted data and IV (server stores binary, checks size after decode)
		plaintext := "test paste content"
		fakeEncData := []byte(plaintext + " [fake encrypted]")

		b64Data := base64.StdEncoding.EncodeToString(fakeEncData)

		iv := make([]byte, 12)
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

		// Read body once for consistent handling
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d: %s", res.StatusCode, string(bodyBytes))
			return
		}

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

		// Test invalid JSON
		invalidBody := bytes.NewReader([]byte(`{invalid json`))
		res, err = srv.Client().Post(srv.URL+"/paste", "application/json", invalidBody)
		if err != nil {
			t.Fatalf("Failed to POST invalid: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 for invalid JSON, got %d", res.StatusCode)
		}

		// Test oversized data (hits post-decode check with +1 byte)
		oversized := make([]byte, int(app.MaxSize)+1)
		b64Oversized := base64.StdEncoding.EncodeToString(oversized)
		oversizedReqBody, _ := json.Marshal(map[string]string{
			"data": b64Oversized,
			"iv":   b64IV,
		})
		res, err = srv.Client().Post(srv.URL+"/paste", "application/json", bytes.NewReader(oversizedReqBody))
		if err != nil {
			t.Fatalf("Failed to POST oversized: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("Expected 413 for oversized, got %d", res.StatusCode)
		}

		// Test invalid IV length
		invalidIV := make([]byte, 11)
		b64InvalidIV := base64.StdEncoding.EncodeToString(invalidIV)
		invalidIVReqBody, _ := json.Marshal(map[string]string{
			"data": b64Data,
			"iv":   b64InvalidIV,
		})
		res, err = srv.Client().Post(srv.URL+"/paste", "application/json", bytes.NewReader(invalidIVReqBody))
		if err != nil {
			t.Fatalf("Failed to POST invalid IV: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 for invalid IV, got %d", res.StatusCode)
		}

		// Test non-POST method
		res, err = srv.Client().Get(srv.URL + "/paste")
		if err != nil {
			t.Fatalf("Failed to GET /paste: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Expected 405 for non-POST, got %d", res.StatusCode)
		}
	})

	t.Run("PasteHandler", func(t *testing.T) {
		// First, create a paste to retrieve
		plaintext := "retrievable paste"
		fakeEncData := []byte(plaintext + " [fake encrypted]")
		b64Data := base64.StdEncoding.EncodeToString(fakeEncData)
		iv := make([]byte, 12)
		if _, err := rand.Read(iv); err != nil {
			t.Fatalf("Failed to generate IV: %v", err)
		}
		b64IV := base64.StdEncoding.EncodeToString(iv)

		reqBody, _ := json.Marshal(map[string]string{"data": b64Data, "iv": b64IV})
		createRes, err := srv.Client().Post(srv.URL+"/paste", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("Failed to create paste for retrieval test: %v", err)
		}
		defer createRes.Body.Close()
		var createResp struct{ ID string }
		createBody, _ := io.ReadAll(createRes.Body)
		json.Unmarshal(createBody, &createResp)
		id := createResp.ID

		// Test GET /p/{id} with JSON Accept
		req, err := http.NewRequest("GET", srv.URL+"/p/"+id, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Accept", "application/json")
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("Failed to GET /p/%s: %v", id, err)
		}
		defer res.Body.Close()

		// Read body once
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("Failed to read body: %v", err)
		}

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 for valid ID, got %d: %s", res.StatusCode, string(bodyBytes))
			return
		}
		if res.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", res.Header.Get("Content-Type"))
		}

		var getResp struct {
			Data string `json:"data"`
			IV   string `json:"iv"`
		}
		if err := json.Unmarshal(bodyBytes, &getResp); err != nil {
			t.Fatalf("Failed to unmarshal get response: %v", err)
		}
		if getResp.Data != b64Data {
			t.Errorf("Expected data %s, got %s", b64Data, getResp.Data)
		}
		if getResp.IV != b64IV {
			t.Errorf("Expected IV %s, got %s", b64IV, getResp.IV)
		}

		// Test GET /p/{id} with default Accept (serves JSON)
		req, err = http.NewRequest("GET", srv.URL+"/p/"+id, nil)
		if err != nil {
			t.Fatalf("Failed to create default request: %v", err)
		}
		res, err = srv.Client().Do(req)
		if err != nil {
			t.Fatalf("Failed to GET default /p/%s: %v", id, err)
		}
		defer res.Body.Close()
		bodyBytes, err = io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("Failed to read default body: %v", err)
		}
		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 for default, got %d", res.StatusCode)
		}
		if res.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json for default accept, got %s", res.Header.Get("Content-Type"))
		}

		// Test GET /p/{id} with HTML Accept (serves template)
		req, err = http.NewRequest("GET", srv.URL+"/p/"+id, nil)
		if err != nil {
			t.Fatalf("Failed to create HTML request: %v", err)
		}
		req.Header.Set("Accept", "text/html")
		res, err = srv.Client().Do(req)
		if err != nil {
			t.Fatalf("Failed to GET HTML /p/%s: %v", id, err)
		}
		defer res.Body.Close()
		bodyBytes, err = io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("Failed to read HTML body: %v", err)
		}
		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 for HTML, got %d", res.StatusCode)
		}
		if res.Header.Get("Content-Type") != "text/html; charset=utf-8" {
			t.Errorf("Expected Content-Type text/html; charset=utf-8 for HTML accept, got %s", res.Header.Get("Content-Type"))
		}
		if !strings.Contains(string(bodyBytes), "<title>Paste</title>") {
			t.Errorf("Expected HTML template for HTML accept")
		}

		// Test non-existent ID
		req, err = http.NewRequest("GET", srv.URL+"/p/nonexistent", nil)
		if err != nil {
			t.Fatalf("Failed to create bad request: %v", err)
		}
		req.Header.Set("Accept", "application/json")
		res, err = srv.Client().Do(req)
		if err != nil {
			t.Fatalf("Failed to GET nonexistent: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("Expected 404 for nonexistent ID, got %d", res.StatusCode)
		}

		// Test invalid path
		req, err = http.NewRequest("GET", srv.URL+"/p/", nil)
		if err != nil {
			t.Fatalf("Failed to create empty ID request: %v", err)
		}
		req.Header.Set("Accept", "application/json")
		res, err = srv.Client().Do(req)
		if err != nil {
			t.Fatalf("Failed to GET /p/: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("Expected 404 for empty ID, got %d", res.StatusCode)
		}

		// Test non-GET method
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
			t.Errorf("Expected 405 for non-GET, got %d", res.StatusCode)
		}
	})

	t.Run("Expiration", func(t *testing.T) {
		// Manually insert an expired paste
		expiredModifier := "-31 days"
		_, err := app.DB.Exec(`INSERT INTO pastes (id, data, iv, created) VALUES (?, ?, ?, datetime('now', ?))`,
			"expired", []byte("fakeb64data"), []byte("fakeb64iv"), expiredModifier)
		if err != nil {
			t.Fatalf("Failed to insert expired paste: %v", err)
		}

		req, err := http.NewRequest("GET", srv.URL+"/p/expired", nil)
		if err != nil {
			t.Fatalf("Failed to create expired request: %v", err)
		}
		req.Header.Set("Accept", "application/json")
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("Failed to GET expired: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusGone {
			t.Errorf("Expected 410 for expired paste, got %d", res.StatusCode)
		}

		// Insert a fresh paste
		_, err = app.DB.Exec(`INSERT INTO pastes (id, data, iv) VALUES (?, ?, ?)`,
			"fresh", []byte("fakeb64data"), []byte("fakeb64iv"))
		if err != nil {
			t.Fatalf("Failed to insert fresh paste: %v", err)
		}

		req, err = http.NewRequest("GET", srv.URL+"/p/fresh", nil)
		if err != nil {
			t.Fatalf("Failed to create fresh request: %v", err)
		}
		req.Header.Set("Accept", "application/json")
		res, err = srv.Client().Do(req)
		if err != nil {
			t.Fatalf("Failed to GET fresh: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 for fresh paste, got %d", res.StatusCode)
		}
	})

	t.Run("IDCollisionHandling", func(t *testing.T) {
		// Create a new app instance with small IDLength to force collisions
		testApp, err := NewApp(":memory:")
		if err != nil {
			t.Fatalf("Failed to create collision test app: %v", err)
		}
		defer testApp.Close()

		testApp.IDLength = 1 // Force quick exhaustion

		// Set up test mux with new method handlers
		testMux := http.NewServeMux()
		testMux.Handle("/static/", http.FileServer(http.FS(content)))
		testMux.HandleFunc("/", testApp.serveIndex)
		testMux.HandleFunc("/paste", testApp.serveCreate)
		testMux.HandleFunc("/p/", testApp.servePaste)
		testSrv := httptest.NewServer(testMux)
		defer testSrv.Close()

		const numInserts = 200
		var ids []string
		dummyB64Data := base64.StdEncoding.EncodeToString([]byte("dummy data"))
		dummyIV := make([]byte, 12)
		if _, err := rand.Read(dummyIV); err != nil {
			t.Fatalf("Failed to generate dummy IV: %v", err)
		}
		dummyB64IV := base64.StdEncoding.EncodeToString(dummyIV)
		reqBody, _ := json.Marshal(map[string]string{"data": dummyB64Data, "iv": dummyB64IV})

		for i := 0; i < numInserts; i++ {
			res, err := testSrv.Client().Post(testSrv.URL+"/paste", "application/json", bytes.NewReader(reqBody))
			if err != nil {
				t.Fatalf("Failed to POST insert %d: %v", i+1, err)
			}

			bodyBytes, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("Failed to read insert %d body: %v", i+1, err)
			}
			res.Body.Close()

			if res.StatusCode != http.StatusOK {
				t.Fatalf("Expected 200 for insert %d, got %d: %s", i+1, res.StatusCode, string(bodyBytes))
			}

			var resp struct{ ID string }
			if err := json.Unmarshal(bodyBytes, &resp); err != nil {
				t.Fatalf("Failed to unmarshal response for insert %d: %v", i+1, err)
			}
			if resp.ID == "" {
				t.Fatalf("Empty ID for insert %d", i+1)
			}
			ids = append(ids, resp.ID)
		}

		if len(ids) != numInserts {
			t.Errorf("Expected %d inserts, got %d", numInserts, len(ids))
		}

		var uniqueCount int
		err = testApp.DB.QueryRow("SELECT COUNT(DISTINCT id) FROM pastes").Scan(&uniqueCount)
		if err != nil {
			t.Fatalf("Failed to query unique count: %v", err)
		}
		if uniqueCount != numInserts {
			t.Errorf("Expected %d unique IDs in DB, got %d", numInserts, uniqueCount)
		}

		var maxLen int
		err = testApp.DB.QueryRow("SELECT MAX(LENGTH(id)) FROM pastes").Scan(&maxLen)
		if err != nil {
			t.Fatalf("Failed to query max ID length: %v", err)
		}
		if maxLen <= testApp.IDLength {
			t.Errorf("Expected max ID length > %d after collisions, got %d", testApp.IDLength, maxLen)
		}

		t.Logf("Sample ID lengths: %v (max: %d)", []int{len(ids[0]), len(ids[50]), len(ids[99]), len(ids[199])}, maxLen)
	})
}
