# 🔐 JWKS Server Project                                                                                                                                                                                                                        ## 📋 Overview                                                                                                          This project implements a secure JSON Web Key Set (JWKS) server in Go.                                                  It features AES encryption for private keys, JWT issuance, user registration with Argon2 password hashing, and authenti>
---

## 🚀 Features
- 🔒 AES-256 encryption of RSA private keys
- 🔐 Issuance of JWTs signed with RSA keys
- 🧑💻 User registration endpoint (`/register`) with UUID password generation and Argon2 secure hashing
- 📜 Logging of authentication requests into a database (`auth_logs`)
- ⚡ Ability to serve expired JWTs for testing (via `?expired=true` query)

---

## 🛠️ Technology Stack
- **Go** (1.20+)
- **SQLite** (serverless embedded database)
- **JWT** (`github.com/golang-jwt/jwt/v5`)
- **UUID** (`github.com/google/uuid`)
- **Argon2 Password Hashing** (`golang.org/x/crypto/argon2`)

---
## 🛠️ Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/your-repo-name.git
cd your-repo-name
module jwks_server

go 1.23.0

toolchain go1.23.8

require github.com/golang-jwt/jwt/v5 v5.2.1

require (
        github.com/google/uuid v1.6.0 // indirect
        github.com/mattn/go-sqlite3 v1.14.24 // indirect
        golang.org/x/crypto v0.37.0 // indirect
        golang.org/x/sys v0.32.0 // indirect
)
