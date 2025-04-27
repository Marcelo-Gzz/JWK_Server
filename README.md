# JWKS Server Project

## 📋 Overview
This project is a JWKS (JSON Web Key Set) server implemented in Go.  
It features AES-256 encryption of RSA private keys, user registration with Argon2 password hashing, JWT issuance, and authentication request logging into SQLite.

## 📦 Features
- 🔒 AES-256 encryption for private keys.
- 🔐 JWT tokens signed with RSA keys.
- 🧑‍💻 User registration with UUID password generation and Argon2 hashing.
- 📜 Logs successful authentication attempts with IP address and user ID.
- ⚡ Supports issuing expired JWTs for testing.

## 🛠️ Technology Stack
- Go 1.20+
- SQLite3
- JWT (github.com/golang-jwt/jwt/v5)
- UUID generation (github.com/google/uuid)
- Argon2 hashing (golang.org/x/crypto/argon2)

## 🚀 Running the Server

1. Install dependencies:
```bash
go mod tidy


 


