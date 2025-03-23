package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
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
	db, err = sql.Open("sqlite3", "private_keys.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys (
		kid TEXT PRIMARY KEY,
		privateKey BLOB,
		expiry INTEGER
	)`) 
	if err != nil {
		log.Fatalf("Failed to create keys table: %v", err)
	}
}

func storeKey(kid string, privateKey *rsa.PrivateKey, expiry time.Time) error {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	_, err := db.Exec(`INSERT OR REPLACE INTO keys (kid, privateKey, expiry) VALUES (?, ?, ?)`, kid, privKeyBytes, expiry.Unix())
	return err
}

func fetchKeys(expired bool) ([]JWK, error) {
	var rows *sql.Rows
	var err error

	if expired {
		rows, err = db.Query(`SELECT kid, privateKey FROM keys WHERE expiry <= ?`, time.Now().Unix())
	} else {
		rows, err = db.Query(`SELECT kid, privateKey FROM keys WHERE expiry > ?`, time.Now().Unix())
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []JWK
	for rows.Next() {
		var kid string
		var privKeyBytes []byte
		if err := rows.Scan(&kid, &privKeyBytes); err != nil {
			return nil, err
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(privKeyBytes)
		if err != nil {
			return nil, err
		}

		pubKey := privateKey.Public().(*rsa.PublicKey)
		keys = append(keys, JWK{
			KID:       kid,
			Algorithm: "RS256",
			KeyType:   "RSA",
			Use:       "sig",
			N:         base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
			E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
		})
	}

	return keys, nil
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	expired := r.URL.Query().Get("expired") == "true"
	var rows *sql.Rows
	var err error

	if expired {
		rows, err = db.Query(`SELECT kid, privateKey FROM keys WHERE expiry <= ? LIMIT 1`, time.Now().Unix())
	} else {
		rows, err = db.Query(`SELECT kid, privateKey FROM keys WHERE expiry > ? LIMIT 1`, time.Now().Unix())
	}

	if err != nil || !rows.Next() {
		http.Error(w, "No valid keys found", http.StatusInternalServerError)
		return
	}

	var kid string
	var privKeyBytes []byte
	if err := rows.Scan(&kid, &privKeyBytes); err != nil {
		http.Error(w, "Failed to read key", http.StatusInternalServerError)
		return
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privKeyBytes)
	if err != nil {
		http.Error(w, "Failed to parse private key", http.StatusInternalServerError)
		return
	}

	exp := time.Now().Add(1 * time.Hour).Unix()
	if expired {
		exp = time.Now().Add(-1 * time.Hour).Unix()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": exp,
	})
	token.Header["kid"] = kid

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": signedToken})
}
