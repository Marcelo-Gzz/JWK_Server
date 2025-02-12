package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	keyExpirationDuration   = 10 * time.Minute
	tokenExpirationDuration = 5 * time.Minute
)

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type Key struct {
	PrivateKey *rsa.PrivateKey
	Kid        string
	Expiry     time.Time
}

var (
	keyStore = struct {
		sync.RWMutex
		keys map[string]Key
	}{keys: make(map[string]Key)}
)

func generateKeyPair() (Key, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Key{}, err
	}

	kid, err := generateKid()
	if err != nil {
		return Key{}, err
	}

	return Key{
		PrivateKey: privateKey,
		Kid:        kid,
		Expiry:     time.Now().Add(keyExpirationDuration),
	}, nil
}

func generateKid() (string, error) {
	bigInt, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bigInt.Bytes()), nil
}

func getJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	keyStore.RLock()
	defer keyStore.RUnlock()

	jwks := JWKS{}
	for _, key := range keyStore.keys {
		if key.Expiry.After(time.Now()) {
			publicKey := key.PrivateKey.Public().(*rsa.PublicKey)
			jwks.Keys = append(jwks.Keys, JWK{
				Kty: "RSA",
				Kid: key.Kid,
				N:   base64.URLEncoding.EncodeToString(publicKey.N.Bytes()),
				E:   base64.URLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	expired := r.URL.Query().Get("expired") == "true"

	keyStore.RLock()
	var signingKey Key
	for _, key := range keyStore.keys {
		if expired && key.Expiry.Before(time.Now()) {
			signingKey = key
			break
		} else if !expired && key.Expiry.After(time.Now()) {
			signingKey = key
			break
		}
	}
	keyStore.RUnlock()

	if signingKey.PrivateKey == nil {
		http.Error(w, "No valid signing key", http.StatusInternalServerError)
		return
	}

	expiryTime := time.Now().Add(tokenExpirationDuration)
	if expired {
		expiryTime = time.Now().Add(-tokenExpirationDuration) // Make it past expiration
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "user123",
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
		"exp": expiryTime.Unix(),
	})
	token.Header["kid"] = signingKey.Kid
	signedToken, err := token.SignedString(signingKey.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": signedToken})
}

func keyRotation() {
	for {
		time.Sleep(5 * time.Minute)
		key, err := generateKeyPair()
		if err != nil {
			log.Println("Key generation failed:", err)
			continue
		}

		keyStore.Lock()
		keyStore.keys[key.Kid] = key
		keyStore.Unlock()
	}
}

func main() {
	key, err := generateKeyPair()
	if err != nil {
		log.Fatal("Failed to generate initial key:", err)
	}

	keyStore.keys[key.Kid] = key
	go keyRotation()

	http.HandleFunc("/.well-known/jwks.json", getJWKS)
	http.HandleFunc("/auth", authHandler)

	log.Println("JWKS Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
