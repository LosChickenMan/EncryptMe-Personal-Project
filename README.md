# EncryptMe — Database Encrypter

A Python desktop application for encrypting and managing the contents of SQLite database files. Developed as an OCR A-Level Computer Science NEA, the project explores the design of a user-facing encryption tool, combining custom cryptographic implementations, relational data management, and a graphical interface.

> **Project status:** Archived educational coursework project. This is a prototype and has not undergone an independent security audit. It should not be used to protect real-world confidential or production data.

## Overview

EncryptMe was designed to make database encryption accessible to users without requiring them to work directly with cryptographic tools or SQL commands. A user can create an account, select a SQLite database, encrypt its supported text fields, and later browse or restore a saved encrypted database.

The implementation was developed iteratively. The encryption logic, database layer, background processing, and interface were built and tested as separate components before being integrated into the application.

## Key features

- **Account management** — registration and login screens with email and password validation, salted password hashing, and account-specific records.
- **SQLite database encryption** — opens a user-selected `.db` file and encrypts values in supported text columns (`CHAR`, `CLOB`, and `TEXT`).
- **AES-256 in CTR mode** — a Python implementation of AES-256 and counter-mode keystream generation, using a per-value nonce and a password-derived key.
- **SHA-256 and salting** — a SHA-256 implementation, alongside randomly generated salts for credential handling and key derivation.
- **Local persistence** — SQLite-backed storage for user records, encrypted items, metadata, and account activity logs.
- **Background processing** — batched database reads and thread-pool workers for encryption and decryption tasks.
- **Progress feedback** — progress indicators and block counters for longer-running operations.
- **Encrypted and decrypted views** — browse stored records, inspect encrypted values, authenticate before decryption, and preview restored database tables.
- **Record management** — open, export, and delete stored database records, with confirmation before permanent deletion.
- **Audit logging** — records account-related actions to support activity tracking.

## How it works

### 1. Authentication

Users register with an email address and password. The documented registration flow validates the input, generates a random salt, and stores hashed credential values rather than storing the password in plaintext. During login, the submitted credentials are processed and compared with the stored values before access is granted.

### 2. Database selection and inspection

The application accepts SQLite `.db` files through a file-selection dialog. It inspects user-defined tables and identifies columns declared with text-oriented SQLite types. Rows are read in batches rather than loading every record into memory at once.

### 3. Encryption

For each supported text value, the application derives an AES-256 key from the supplied password and salt, generates a nonce, and uses AES-256 in Counter (CTR) mode to produce ciphertext. The nonce is stored with the ciphertext so that the corresponding keystream can be reconstructed during decryption. The combined value is Base64-encoded before being written back into the database.

The AES implementation is decomposed into smaller operations, including key expansion, `SubBytes`, `ShiftRows`, `MixColumns`, and `AddRoundKey`. Helper functions handle byte conversion, state-matrix manipulation, word operations, and keystream generation.

### 4. Storage and retrieval

The application uses a local SQLite database with three principal tables:

| Table | Purpose |
| --- | --- |
| `users` | Stores account identifiers, hashed credentials, salts, and timestamps. |
| `encrypted_items` | Stores encrypted database records, associated metadata, salts, and binary payloads. |
| `logs` | Records user actions and related event details. |

Database operations are organised through reusable functions and a `DatabaseManager` class. The implementation uses parameterised SQL statements for database writes and lookups, and foreign-key relationships to associate records and logs with users.

### 5. Decryption and viewing

When a user opens a saved record, the application requests the relevant password and checks it before starting decryption. The database is processed in batches, and the interface reports progress. The restored SQLite data can then be previewed through a table-based interface with pagination, or exported by the user.

## Design and implementation

The project is organised around four main responsibilities:

| Component | Responsibility |
| --- | --- |
| Cryptography | SHA-256 hashing, salt generation, AES-256 key expansion, CTR keystream generation, encryption, and decryption. |
| Database management | SQLite initialisation, account storage, encrypted-record persistence, retrieval, deletion, and audit events. |
| User interface | Tkinter screens for registration, login, navigation, encryption, record viewing, and account actions. |
| Processing workers | Batched row processing, thread-pool execution, progress reporting, and database transformation. |

The interface uses Tkinter frames, canvas elements, widgets, and event bindings. The main menu exposes the primary actions — **Encrypt My Data**, **View My Files**, and **Account Actions** — while the encryption and viewing screens provide status feedback and record controls.

## Technology stack

- **Language:** Python (the coursework records Python 3.13.2 as the development environment)
- **GUI:** Tkinter
- **Database:** SQLite, accessed through Python's `sqlite3` module
- **Cryptography:** SHA-256 and AES-256-CTR implementations documented in the project
- **Data representation:** Python byte strings, SQLite BLOB values, and Base64 encoding
- **Concurrency:** Python threads and thread-pool workers for database processing

The original coursework document does not specify a definitive application entry-point command or a complete dependency manifest. Check the repository's source files and dependency files for the correct installation and launch instructions.

## Testing and evaluation

Testing was carried out throughout development, with separate checks for the hashing algorithm, AES operations, database methods, and interface workflows. The coursework documents debugging work on bitwise operations, byte order, AES state layout, round-key handling, and database record retrieval.

The final functional checklist records successful tests for:

- Valid and invalid account registration and login inputs.
- Password length and complexity validation.
- Selection of valid `.db` files and rejection of unsupported file types.
- Encryption of a selected database using a supplied password.
- Retrieving and viewing saved encrypted records.
- Rejecting an incorrect password during decryption.
- Viewing the restored database and accessing account activity logs.

The processing workers were also exercised against SQLite test databases ranging from **16 KB to 1 GB**, with CPU and memory usage recorded. These are coursework test observations, not independent benchmarks or a guarantee of performance on other systems.

## Known limitations and security considerations

This project is useful as a demonstration of algorithm development and software engineering, but its documented limitations are significant. They should be understood before running it with any data that matters.

- **AES-CTR does not authenticate ciphertext.** CTR mode provides confidentiality but does not, by itself, detect tampering. A modified ciphertext may decrypt to modified plaintext without an authentication failure. A production implementation should use an authenticated mode such as AES-GCM, or add a correctly designed authentication mechanism.
- **Nonce uniqueness is essential.** A nonce must never be reused with the same key. Reuse can compromise the confidentiality of data encrypted under that key.
- **The cryptographic routines are educational implementations.** SHA-256 and AES-256 are implemented in application code as part of the coursework. They have not been independently audited or subjected to a comprehensive cryptographic test programme. Production software should use established, maintained cryptographic libraries rather than custom cipher implementations.
- **Encryption coverage is limited by SQLite column types.** The documented worker targets text-oriented columns (`CHAR`, `CLOB`, and `TEXT`). Numeric values and other unsupported types are not encrypted, so database structure and some content may remain visible.
- **Credential handling is not production-grade.** The coursework uses salted SHA-256 for account credentials. A production system should use a dedicated password-hashing scheme with an appropriate work factor, such as Argon2id, scrypt, or PBKDF2.
- **Original data is retained in application storage.** The coursework's storage design describes keeping both original and encrypted database BLOBs in the `encrypted_items` table. This means the local application database should not be assumed to contain ciphertext only.
- **Key exposure and session handling need improvement.** Encryption keys exist in the Python process while operations run; the coursework also identifies the absence of automatic inactivity logout and the possibility of exposure through memory dumps or swap.
- **Large database workflows need further hardening.** The evaluation identifies gaps around UI responsiveness, progress feedback, validation, overwrite protection, corrupted ciphertext detection, versioning, and rollback after a failed decryption.

For these reasons, treat the application as a learning prototype. Do not use it as the sole protection for personal, financial, business, or otherwise sensitive information.

## Potential future development

The coursework identifies several possible improvements:

1. Replace or supplement CTR mode with AES-GCM to provide authenticated encryption.
2. Replace custom cryptographic routines and the password-storage scheme with established, maintained implementations.
3. Extend encryption coverage to non-text SQLite values where appropriate, while preserving database types and constraints.
4. Improve key lifecycle management, session timeouts, recovery, and protection against accidental data loss.
5. Add stronger integrity checks, encrypted-record versioning, rollback support, and more comprehensive automated testing.
6. Refine progress reporting and interface responsiveness for large databases.

## Project context

This repository preserves an earlier A-Level Computer Science coursework project. Its main value is as a record of the design and development process: problem decomposition, algorithm implementation, object-oriented structure, database design, iterative debugging, test planning, and evaluation of technical limitations.
