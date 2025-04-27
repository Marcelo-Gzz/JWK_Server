package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func main() {
	initializeDatabase()
	genKeys()

	http.HandleFunc("/.well-known/jwks.json", JWKSHandler)
	http.HandleFunc("/auth", AuthHandler)
	http.HandleFunc("/register", RegisterHandler)

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

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		email TEXT UNIQUE,
		date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_login TIMESTAMP
	)`)
	if err != nil {
		log.Fatalf("Failed to create users table: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS auth_logs(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_ip TEXT NOT NULL,
		request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		user_id INTEGER,
		FOREIGN KEY(user_id) REFERENCES users(id)
	)`)
	if err != nil {
		log.Fatalf("Failed to create auth_logs table: %v", err)
	}
}

func genKeys() {
	goodPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	expiredPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	storeKey(goodPrivKey, time.Now().Add(1*time.Hour))
	storeKey(expiredPrivKey, time.Now().Add(-1*time.Hour))
}

func storeKey(privateKey *rsa.PrivateKey, expiry time.Time) (int64, error) {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	aesKey, err := loadAESKey()
	if err != nil {
		return 0, err
	}

	privKeyBytes = pkcs7Pad(privKeyBytes, aes.BlockSize)

	encryptedKey, err := encrypt(privKeyBytes, aesKey)
	if err != nil {
		return 0, err
	}

	result, err := db.Exec(`INSERT INTO keys (key, exp) VALUES (?, ?)`, encryptedKey, expiry.Unix())
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
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
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

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
		if err := rows.Scan(&kid, &privKeyBytes); err != nil {
			continue
		}

		aesKey, err := loadAESKey()
		if err != nil {
			http.Error(w, "Encryption key missing", http.StatusInternalServerError)
			return
		}

		decryptedPrivKeyBytes, err := decrypt(privKeyBytes, aesKey)
		if err != nil {
			http.Error(w, "Failed to decrypt key", http.StatusInternalServerError)
			return
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(decryptedPrivKeyBytes)
		if err != nil {
			http.Error(w, "Failed to parse decrypted key", http.StatusInternalServerError)
			return
		}

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
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Username string `json:"username"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var userID int
	err := db.QueryRow(`SELECT id FROM users WHERE username = ?`, request.Username).Scan(&userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
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

	aesKey, err := loadAESKey()
	if err != nil {
		http.Error(w, "Encryption key missing", http.StatusInternalServerError)
		return
	}

	decryptedPrivKeyBytes, err := decrypt(privKeyBytes, aesKey)
	if err != nil {
		http.Error(w, "Failed to decrypt key", http.StatusInternalServerError)
		return
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(decryptedPrivKeyBytes)
	if err != nil {
		http.Error(w, "Failed to parse decrypted key", http.StatusInternalServerError)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": request.Username,
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

	ip := r.RemoteAddr

	_, err = db.Exec(`INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)`, ip, userID)
	if err != nil {
		log.Println("Failed to log authentication event:", err)
	}
}

func loadAESKey() ([]byte, error) {
	key := os.Getenv("NOT_MY_KEY")
	if key == "" {
		return nil, errors.New("NOT_MY_KEY environment variable is not set")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	if len(keyBytes) != 32 {
		return nil, errors.New("AES key must be 32 bytes for AES-256")
	}

	return keyBytes, nil
}

func encrypt(plainData []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plainData))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plainData)

	return ciphertext, nil
}

func decrypt(cipherData []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(cipherData) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := cipherData[:aes.BlockSize]
	cipherData = cipherData[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherData, cipherData)

	return pkcs7Unpad(cipherData)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid padding size")
	}
	padding := int(data[length-1])
	if padding > length {
		return nil, errors.New("invalid padding size")
	}
	return data[:(length - padding)], nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash), nil
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	newPassword := uuid.New().String()

	hashedPassword, err := hashPassword(newPassword)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(`INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)`, request.Username, hashedPassword, request.Email)
	if err != nil {
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	response := map[string]string{"password": newPassword}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
