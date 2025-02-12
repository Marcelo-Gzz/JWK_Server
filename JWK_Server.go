package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Key struct {
	KID        string    `json:"kid"`
	PrivateKey *rsa.PrivateKey
	PublicKey  string    `json:"key"`
	ExpiresAt  time.Time `json:"exp"`
}

type JWKS struct {
	Keys []map[string]interface{} `json:"keys"`
}

var (
	keyStore = make(map[string]Key)
	mutex    = sync.Mutex{}
	rateLimit = make(map[string]time.Time) // Rate limiting map
)

const (
	keyValidity  = 5 * time.Minute
	jwtValidity  = 10 * time.Minute
	port         = ":8080"
	rateLimitTTL = 10 * time.Second
)

func generateRSAKey() (*rsa.PrivateKey, string, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, "", err
    }

    // Convert public key to PEM format
    publicKeyASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
    if err != nil {
        return nil, "", err
    }

    publicKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyASN1,
    })

    return privateKey, string(publicKeyPEM), nil
}

func refreshKeys() {
	mutex.Lock()
	defer mutex.Unlock()

	// Remove expired keys
	now := time.Now().UTC()
	for k, v := range keyStore {
		if now.After(v.ExpiresAt) {
			delete(keyStore, k)
		}
	}

	// Generate new key
	key, err := generateRSAKey()
	if err == nil {
		keyStore[key.KID] = key
	}
}

func getJWKSHandler(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()

	var jwks JWKS
	for _, k := range keyStore {
		if time.Now().Before(k.ExpiresAt) {
			jwks.Keys = append(jwks.Keys, map[string]interface{}{
				"kty": "RSA",
				"kid": k.KID,
				"n":   base64.RawURLEncoding.EncodeToString(k.PrivateKey.N.Bytes()),
				"e":   "AQAB",
			})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()

	clientIP := r.RemoteAddr
	if lastRequest, exists := rateLimit[clientIP]; exists && time.Since(lastRequest) < rateLimitTTL {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}
	rateLimit[clientIP] = time.Now()

	expired := r.URL.Query().Get("expired") == "true"
	var key Key
	for _, k := range keyStore {
		if (expired && time.Now().After(k.ExpiresAt)) || (!expired && time.Now().Before(k.ExpiresAt)) {
			key = k
			break
		}
	}

	if key.KID == "" {
		http.Error(w, "No valid keys found", http.StatusInternalServerError)
		return
	}

	claims := jwt.MapClaims{
		"sub": "user",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(jwtValidity).Unix(),
		"kid": key.KID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(key.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	response := map[string]string{"token": signedToken}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	// Initialize keys at startup
	refreshKeys()

	// Start the key refresh routine
	go func() {
		for {
			time.Sleep(keyValidity / 2)
			refreshKeys()
		}
	}()

	// Start the HTTP server
	http.HandleFunc("/.well-known/jwks.json", getJWKSHandler)
	http.HandleFunc("/auth", authHandler)

	fmt.Println("JWKS Server running on port", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
