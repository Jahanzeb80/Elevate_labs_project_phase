File Encryptor - made by Cyber Warrior

Overview

This is simple "The File Encryptor" tool made with python and tkinter GUI.
Its allow you to encrypt and decrypt any file (PDF, image, ZIP, DOCX, etc.) securely using AES 256 encryption using password protection and integrity verification.


Features

AES-256 file encryption   
Uses PBKDF2 key derivation with salt & IV for strong security  
Integrity check (with SHA-256 hash)  
Simple, beginner-friendly GUI  
Written in pure Python


How it Works

Pick a file you want to encrypt.  
Enter a strong password (only you know it).  
The tool encrypts the file → saves `.enc` file + `.meta.json` for integrity check.(asks for path to save the file)  
To decrypt, select the `.enc` file and enter the same password (you set during encryption) → get the original file back.


Requirements

- Python 3.x
- [`cryptography`](https://pypi.org/project/cryptography/)

