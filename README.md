# 🔐 CLI Password Manager

A secure command-line password manager built with Python. Stores credentials locally with AES (Fernet) encryption and bcrypt master password protection.

---

## ✨ Features

- 🔑 **Master password authentication**: Uses `bcrypt` for secure hashing.
- 🔒 **AES encryption**: All saved passwords are symmetrically encrypted using Fernet before storage.
- 🗄️ **SQLite local storage**: Lightweight, contained database for portable and fast access.
- ➕ **Full CRUD Features**: Add, view, edit, and delete credentials seamlessly.
- 🔄 **Master Password Update**: Safely change your master password and re-encrypt your entire vault dynamically.
- 💻 **Clean CLI interface**: Interactive looping terminal menu for ease of use.

---

## 🛠️ Tech Stack

![Python](https://img.shields.io/badge/Python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)

---

## 📁 Project Structure

```
cli-password-manager/
├── main.py              # Entry point and menu loop
├── requirements.txt     # Python Dependencies
├── utils/
│   ├── auth.py          # Master password handling with bcrypt
│   ├── encryption.py    # Key derivation & Fernet encryption
│   └── database.py      # SQLite operations
└── README.md
```

---

## ⚙️ Installation & Usage

**1. Clone the repository**
```bash
git clone https://github.com/NTgGamer1/cli-password-manager.git
cd cli-password-manager
```

**2. Install requirements**
*Note: Depending on your Python configuration (e.g. MacOS Homebrew PEP 668), you may need to append `--break-system-packages` or use a `venv`.*
```bash
python3 -m pip install -r requirements.txt
```

**3. Run the Application**
```bash
python3 main.py
```

### 🚨 Wait! First-Time Configuration 🚨
Upon your very first launch of this app, the vault will automatically generate itself and assign you the default master password:

> **Default Master Password**: `mysecret`

Once you successfully log in using this default password, please select **Option 5: Change Master Password** from the menu immediately to secure your specific installation.

---

## 🚀 Menu Options

Once authenticated, you will be interacting with a continuous loop menu:

```
--- Main Menu ---
1. Add a new password
2. View all saved passwords
3. Edit a password
4. Delete a password
5. Change Master Password
6. Exit
-----------------
```

---

## 🔒 Security Summary

- All passwords encrypted with AES-128 via `cryptography.fernet` before storage.
- The AES session key is mathematically derived using `PBKDF2HMAC`.
- Your primary Master password is mathematically hashed using `bcrypt` (never saved!).
- Local only execution — no cloud, no sync, no outside tracking.

---

## 📌 Status

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat-square)

---

## 👤 Author

**Nikhil Maurya** — [@NTgGamer1](https://github.com/NTgGamer1)
