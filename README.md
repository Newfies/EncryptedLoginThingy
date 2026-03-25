# 🔐 Secure Bcrypt SQLite Login System

---

## ✨ Features

*   **🔑 Encryption** – Passwords are salted and hashed using `bcrypt` (12 rounds).
*   **🗄️ SQL Database** – Zero-config SQL setup using `sqlite3`.
*   **⚡ Admin Control** – A pre-made `server` account with the exclusive power to wipe and re-initialize the user database remotely.
*   **⚙️ .env** – Fully configurable via `.env` for ports, secrets, and admin credentials.

---

### Installation
Clone the repository and run the automated setup script:

```bash
git clone https://github.com/Newfies/secure-bcrypt-sqlite-login-system.git
cd secure-bcrypt-sqlite-login-system
install.bat
```

### Running the Server
To start the application, simply execute:

```bash
run.bat
```
