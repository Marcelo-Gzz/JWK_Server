JWKS Server Project

Overview
This project implements a RESTful JSON Web Key Set (JWKS) server using SQLite for key storage. The server is capable of generating JWTs, serving public keys via JWKS, and handling requests for expired keys.

Features
- **SQLite Integration:** Private keys are stored persistently in a database file (`totally_not_my_privateKeys.db`).
- **Endpoints:**
  - `POST /auth`: Generates a signed JWT using a valid or expired key.
  - `GET /.well-known/jwks.json`: Serves public keys from the database.
- **Key Management:** Automatically generates a valid key and an expired key on startup.

---
How to Run  

How To Install Go (If Not Already Installed)

Download and Install Go:

Visit Go Downloads

Download the latest stable version.

Follow the installation instructions for your OS (Windows, Mac, Linux).

Verify Installation:

 go version

Should output something like:  

go version go1.20.5 linux/amd64

CLONE THE REPO
 git clone https://github.com/YourUsername/YourRepository.git
 cd YourRepository  

 INSTALL DEPENDANCIES 
  git clone https://github.com/YourUsername/YourRepository.git
 cd YourRepository

RUN THE SERVER IN THE BACKGROUND
go run JWK_Server.go & 

RUN GRADEBOT 
./gradebot project2 --port 8080 --debug

STOP SERVER 
ps -aux | grep JWK_Server
kill -9 <PID>



 


