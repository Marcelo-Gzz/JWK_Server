package main

import (
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
)

func TestJWKSHandler(t *testing.T) {
        initializeDatabase()
        genKeys()

        req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
        w := httptest.NewRecorder()

        JWKSHandler(w, req)

        resp := w.Result()
        if resp.StatusCode != http.StatusOK {
                t.Fatalf("Expected status OK, got %v", resp.Status)
        }
}

func TestRegisterHandler(t *testing.T) {
        initializeDatabase() 
   body := strings.NewReader(`{"username":"testuser","email":"testuser@example.com"}`)
        req := httptest.NewRequest(http.MethodPost, "/register", body)
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()

        RegisterHandler(w, req)

        resp := w.Result()
        if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
                t.Fatalf("Expected status OK or Created, got %v", resp.Status)
        }
}


