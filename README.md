# 🔐 JWKS Server Project

## 📋 Overview
This project implements a secure JSON Web Key Set (JWKS) server in Go.  
It features AES encryption for private keys, JWT issuance, user registration with Argon2 password hashing, and authentication request logging using SQLite.

---

## 🚀 Features
- 🔒 AES-256 encryption of RSA private keys
- 🔐 Issuance of JWTs signed with RSA keys
- 🧑‍💻 User registration endpoint (`/register`) with UUID password generation and Argon2 secure hashing
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

---

## 🤖 AI Usage Acknowledgement

I used OpenAI's ChatGPT to assist with specific parts of this project.  
Mainly, I used it to:
- Help troubleshoot specific Go errors (such as AES encryption and JWT signing issues).
- Suggest ways to organize my code more cleanly.
- Provide examples for writing a README and small unit tests.

The majority of the code and debugging was done manually.  
General prompts used included:
- "How to encrypt with AES in Go"
- "Example of a simple JWT creation in Go"
- "How to run go test with coverage"

All AI suggestions were verified, tested, and adapted to meet the assignment requirements.

---


