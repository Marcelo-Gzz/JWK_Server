package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/golang-jwt/jwt/v5"
)

var db *sql.DB

func main() {
	initializeDatabase()
	genKeys()
	http.HandleFunc("/.well-known/jwks.json", JWKSHandler)
	http.HandleFunc("/auth", AuthHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func initializeDatabase() {
	var err error
	db, err = sql.Open("sqlite3", "totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys (
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`) 
	if err != nil {
		log.Fatalf("Failed to create keys table: %v", err)
	}
}

func storeKey(privateKey *rsa.PrivateKey, expiry time.Time) (int64, error) {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	result, err := db.Exec(`INSERT INTO keys (key, exp) VALUES (?, ?)`, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privKeyBytes}), expiry.Unix())
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func genKeys() {
	goodPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	expiredPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	
	storeKey(goodPrivKey, time.Now().Add(1*time.Hour))     // Store good key
	storeKey(expiredPrivKey, time.Now().Add(-1*time.Hour))  // Store expired key
}

type JWK struct {
	KID       string `json:"kid"`
	Algorithm string `json:"alg"`
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	N         string `json:"n"`
	E         string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT kid, key FROM keys WHERE exp > ?`, time.Now().Unix())
	if err != nil {
		http.Error(w, "Failed to fetch keys", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var keys []JWK

	for rows.Next() {
		var kid int64
		var privKeyBytes []byte
		err := rows.Scan(&kid, &privKeyBytes)
		if err != nil {
			continue
		}

		block, _ := pem.Decode(privKeyBytes)
		privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
		pubKey := privateKey.Public().(*rsa.PublicKey)

		jwk := JWK{
			KID:       strconv.FormatInt(kid, 10),
			Algorithm: "RS256",
			KeyType:   "RSA",
			Use:       "sig",
			N:         base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
			E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
		}
		keys = append(keys, jwk)
	}

	resp := JWKS{Keys: keys}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	expired := r.URL.Query().Get("expired") == "true"
	query := `SELECT kid, key FROM keys WHERE exp > ? LIMIT 1`
	if expired {
		query = `SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1`
	}

	row := db.QueryRow(query, time.Now().Unix())

	var kid int64
	var privKeyBytes []byte
	if err := row.Scan(&kid, &privKeyBytes); err != nil {
		http.Error(w, "No valid keys found", http.StatusInternalServerError)
		return
	}

	block, _ := pem.Decode(privKeyBytes)
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = strconv.FormatInt(kid, 10)

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	response := map[string]string{"token": signedToken}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
