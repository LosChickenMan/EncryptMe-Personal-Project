# Database Encrypter

A local desktop application that encrypts the text contents of SQLite databases using AES-256 (CTR mode), with a multi-user login system and a simple GUI. Built in Python as my OCR Computer Science NEA (A-Level coursework) at Ark Isaac Newton Academy.

> **Status:** Coursework project. See [Limitations](#limitations) for known security trade-offs.

## What it does

Ransomware, SQL injection and data leaks are a growing problem for individuals and small businesses. This program lets a user take a `.db` file, protect it with a password, and later decrypt it again, all on their own machine with nothing sent over a network.

- **Account system.** Users sign up and log in with a username, email and password. Passwords are salted and hashed, never stored in plaintext.
- **Database encryption.** Select a `.db` file and a password. The program derives an AES-256 key from the password and a random salt, then encrypts every text column (`CHAR`, `CLOB`, `TEXT`) in every user table.
- **Decrypt and view.** Previously encrypted databases can be decrypted and viewed with the correct password.
- **Progress feedback.** Encryption runs in worker threads, with a live progress bar based on the number of 16-byte AES blocks to process.
- **Activity logging.** Events such as failed logins are recorded in a logs table with timestamps.
- **Input validation.** Email format, password strength, empty input and file-type checks (only `.db` files can be selected).

## How it works

The solution was decomposed into three parts:

| Component | Responsibility |
|---|---|
| **User interface** | Tkinter GUI: home, sign up / login, main menu, encrypt data, view data |
| **Encryption** | Key derivation, AES-256-CTR encryption and decryption, password hashing and salting |
| **Database storage** | SQLite tables for users, encrypted data and logs; helper methods to store and return encrypted databases |

**Encryption pipeline**

1. The user's password is combined with a randomly generated salt and run through PBKDF2-HMAC to derive a 256-bit key.
2. The database is copied to a temporary file and all user tables are scanned for text columns.
3. Each text cell is encrypted with AES-256-CTR using a fresh random 12-byte nonce.
4. The result is stored back in the same cell as `base64(nonce || ciphertext)`.
5. The salt and algorithm details are saved in a metadata table so the database can be decrypted later.

**Worker and resource management functions**

- `estimate_total_text_blocks_in_file` and `estimate_total_text_blocks_in_encrypted_bytes` count the 16-byte AES blocks in a plain or encrypted database. They are used to plan the work and to verify that everything was encrypted.
- `_iter_fetchmany` is a generator that reads rows in small chunks so large databases don't need to fit in memory.
- `encrypt_db_attributes_worker` encrypts batches of rows in parallel with a thread pool. It uses a lock-protected shared counter for progress, and `root.after(0, ...)` to update Tkinter safely from the main thread.

## Tech stack

- **Python 3**
- **Tkinter** for the GUI (native, no extra install)
- **SQLite** (`sqlite3`) for local storage
- **`cryptography`** for AES-256 and PBKDF2-HMAC
- **`hashlib`** and **`os.urandom`** for SHA-256 hashing and secure random salts and nonces

I chose to use established libraries rather than writing cryptographic primitives from scratch. My first attempt at hand-written AES-CTR ran into counter and nonce-size problems, which is documented in the write-up.

## Getting started

```bash
# 1. Clone the repository
git clone https://github.com/[your-username]/[repo-name].git
cd [repo-name]

# 2. Install dependencies
pip install cryptography

# 3. Run the program
python [main_file].py
```

Tkinter and SQLite ship with standard Python installs. On some Linux distributions you may need to install Tkinter separately (for example `sudo apt install python3-tk`).

## Usage

1. Create an account on the sign-up page, then log in.
2. From the main menu choose **Encrypt Data**.
3. Pick a `.db` file and enter a password.
4. Wait for the progress bar to finish.
5. To read the data again, choose **View Data**, select the encrypted database and enter the same password.

## Project documentation

The full write-up covers the whole development process:

- Problem analysis, stakeholder research and a 50-person questionnaire
- Language and library justification
- Success criteria, top-down decomposition and variable table
- Iterative development with test evidence for the encryption, database and UI classes
- Post-development testing (valid, boundary, erroneous and null cases), beta testing with three stakeholders, and evaluation

The report is in [`docs/`]([link-to-pdf]).

## Testing

Tests were run against a table covering email validation, password validation, database file validation and security checks. Examples:

| Test | Input | Expected result |
|---|---|---|
| Email, valid | `newemail@gmail.com` | Accepted |
| Email, erroneous | `[];[[];` | "Invalid Email Format" |
| Password, boundary | `Abc1234` | "Password must be at least 8 characters" |
| Password, erroneous | `password` | "Password must include at least 1 number" |
| Database, erroneous | `employee.json` | Cannot be selected, `.db` files only |
| Security, valid | Correct password | Database fully decrypted and readable |
| Security, erroneous | Wrong password | Error shown, no decryption |

## Limitations

- **No authentication on the ciphertext.** AES-CTR gives confidentiality but not integrity. Encrypted cells could be modified without detection. A production version should use AES-GCM, or CTR with an HMAC.
- **Only text columns are encrypted.** Numeric, blob and schema data are left as they are.
- **Not independently security-tested.** The implementation has not been audited or stress-tested against advanced attacks, so I class "strong encryption" as only partially met in my own evaluation.
- **Single machine, desktop only.** There is no key sharing or multi-user access to the same database.

## Possible future work

- Switch to an authenticated mode (AES-GCM)
- Hybrid encryption with RSA key pairs so several users can share one database
- Progress estimate with time remaining, and an "advanced details" panel explaining the encryption (both requested during beta testing)
- Modern GUI toolkit (for example NiceGUI)
- Plugin-based encryption modules and CI/CD with automated tests

## Author

**Ismail Raza Choudhury**
OCR Computer Science NEA, Ark Isaac Newton Academy

## Licence

[Choose a licence, or state "All rights reserved" for coursework.]
