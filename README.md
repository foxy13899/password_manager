# 🔐 AES-Encrypted Password Manager (CLI)

A simple yet secure command-line password manager written in Python. It uses AES-256 encryption (CBC mode) to securely store credentials, along with SHA-512 for master password authentication. All data is saved locally in an encrypted and encoded format for maximum privacy and portability.

---

## 📦 Features

- **AES-256 Encryption**: Encrypts passwords using a securely generated key and IV.
- **Master Password Authentication**: Uses SHA-512 to verify the master key.
- **Password Generation**: Built-in strong password generator with custom options.
- **Secure Storage**: Encrypted entries are base64-encoded and stored in `pass.json`.
- **Human-Friendly Interface**: Simple CLI with clear options and commands.
- **Cross-Platform Compatibility**: Works on both Windows and UNIX-like systems.

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/foxy13899/password_manager
cd password-manager
```

### 2. Install Dependencies

Make sure Python 3.7+ is installed. Install required packages via pip:

```bash
pip install pycryptodome python-dotenv tabulate
```

### 3. Run the Program

```bash
python password_manager.py
```

On first launch, you'll be prompted to set a master password. You'll need to access your stored credentials in future sessions.

---

## 🔧 Usage

Once inside the CLI, you can choose from several options:

```
Options:
1: Add or change a password
2: View a password
3: Generate a new password
4: View saved password platforms
5 or KeyboardInterrupt: Exit
clr: Clear screen
options: Show this menu
```

### ✅ Add or Change Password

You will be prompted to enter:
- Platform name (e.g., "Gmail")
- Account identifier or username
- Password (manually or from the generator)

Passwords are encrypted and saved in `pass.json`.

### 🔍 View Passwords

Select the platform name to decrypt stored entries. You will then see all associated accounts and passwords in a readable format.

### 🔐 Generate Password

You can generate strong passwords with customizable length and character sets (with or without symbols).

---

## 📁 File Structure

- `password_manager.py`: Main script
- `pass.json`: Encrypted password storage
- `pass.env`: Environment file storing the hashed master key

---

## 🔒 Security Notes

- All passwords are encrypted using AES-256 (CBC mode) with a unique IV.
- The master key is verified using SHA-512 hashing.
- Base64 is used to make encrypted values JSON-safe.
- Stored data never leaves your machine.
- Consider implementing PBKDF2 or bcrypt for key derivation in future versions.

---

## 🧠 Future Improvements

- Add password expiry reminders
- Export/import encrypted backups
- Auto-lock after inactivity
- GUI wrapper (e.g., with Tkinter or PyQt)

---

## 📝 License

This project is open-source and available under the MIT License. Feel free to use and modify it for personal use.

---
