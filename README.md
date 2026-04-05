# 🔐 CLI Password Manager

A secure command-line password manager built with Python. Stores credentials locally with AES encryption and master password protection.

---

## ✨ Features

- 🔑 Master password authentication
- 🔒 AES encryption for all stored passwords
- 🗄️ SQLite local storage
- ➕ Add, view, search, and delete credentials
- 🔁 Built-in password generator
- 💻 Clean CLI interface

---

## 🛠️ Tech Stack

![Python](https://img.shields.io/badge/Python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)

---

## 📁 Project Structure

```
cli-password-manager/
├── main.py              # Entry point
├── requirements.txt     # Dependencies
├── utils/
│   ├── auth.py          # Master password handling
│   ├── encryption.py    # AES encryption/decryption
│   └── database.py      # SQLite operations
└── README.md
```

---

## ⚙️ Installation

```bash
# Clone the repo
git clone https://github.com/NTgGamer1/cli-password-manager.git
cd cli-password-manager

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```

---

## 🚀 Usage

```
Options:
  1. Add a new password
  2. View all passwords
  3. Search by service name
  4. Delete a password
  5. Generate a strong password
  6. Exit
```

---

## 🔒 Security

- All passwords encrypted with AES-256 before storage
- Master password is hashed using bcrypt — never stored in plain text
- Local only — no cloud, no sync, no tracking

---

## 📌 Status

![Status](https://img.shields.io/badge/Status-In%20Progress-orange?style=flat-square)

---

## 👤 Author

**Nikhil Maurya** — [@NTgGamer1](https://github.com/NTgGamer1)
