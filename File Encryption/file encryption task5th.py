import os
import json
import hashlib
from datetime import datetime

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# --- Constants ---
KEY_LENGTH = 32
IV_LENGTH = 16
SALT_LENGTH = 16
ITERATIONS = 100_000

# --- PBKDF2 Key Derivation ---
def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password)

# --- Encrypt File ---
def encrypt_file(file_path: str, password: str):
    try:
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        salt = os.urandom(SALT_LENGTH)
        iv = os.urandom(IV_LENGTH)
        key = derive_key(password.encode(), salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        pad_length = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + bytes([pad_length] * pad_length)

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        enc_file = file_path + '.enc'
        with open(enc_file, 'wb') as f:
            f.write(salt + iv + ciphertext)

        file_hash = hashlib.sha256(plaintext).hexdigest()
        metadata = {
            'original_name': os.path.basename(file_path),
            'encrypted_name': os.path.basename(enc_file),
            'timestamp': datetime.utcnow().isoformat(),
            'sha256': file_hash
        }

        with open(enc_file + '.meta.json', 'w') as f:
            json.dump(metadata, f)

        messagebox.showinfo("Success", f"✅ Encrypted:\n{enc_file}\nMetadata saved:\n{enc_file}.meta.json")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# --- Decrypt File ---
def decrypt_file(enc_file: str, password: str):
    try:
        with open(enc_file, 'rb') as f:
            data = f.read()

        salt = data[:SALT_LENGTH]
        iv = data[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
        ciphertext = data[SALT_LENGTH + IV_LENGTH:]

        key = derive_key(password.encode(), salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        pad_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-pad_length]

        with open(enc_file + '.meta.json', 'r') as f:
            metadata = json.load(f)

        file_hash = hashlib.sha256(plaintext).hexdigest()
        if file_hash != metadata['sha256']:
            messagebox.showerror("Error", "❌ Hash mismatch! File may be tampered.")
            return

        out_name = 'decrypted_' + metadata['original_name']
        with open(out_name, 'wb') as f:
            f.write(plaintext)

        messagebox.showinfo("Success", f"✅ Decrypted:\n{out_name}\nIntegrity verified.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# --- GUI handlers ---
def choose_encrypt_file():
    file_path = filedialog.askopenfilename(title="Select file to encrypt")
    if not file_path:
        return
    password = simpledialog.askstring("Password", "Enter password:", show='*')
    if password:
        encrypt_file(file_path, password)

def choose_decrypt_file():
    file_path = filedialog.askopenfilename(title="Select .enc file to decrypt")
    if not file_path:
        return
    password = simpledialog.askstring("Password", "Enter password:", show='*')
    if password:
        decrypt_file(file_path, password)

# -------------------- GUI -------------------- #
root = tk.Tk()
root.title("🔒 File Encryptor - Cyber Warrior")
root.geometry("600x400")
root.configure(bg="#1f1f1f")
root.resizable(False, False)

title_label = tk.Label(root, text="File Encryptor", font=("Helvetica", 24, "bold"), fg="#00ff99", bg="#1f1f1f")
title_label.pack(pady=40)

desc_label = tk.Label(root, text="Encrypt & Decrypt files with AES-256 + integrity check.",
                      font=("Helvetica", 12), fg="#ccc", bg="#1f1f1f")
desc_label.pack(pady=10)

encrypt_btn = ttk.Button(root, text="Encrypt File 🔐", command=choose_encrypt_file)
encrypt_btn.pack(pady=30)

decrypt_btn = ttk.Button(root, text="Decrypt File 🔓", command=choose_decrypt_file)
decrypt_btn.pack(pady=10)

credit_label = tk.Label(root, text="🔒 Made by Cyber Warrior", font=("Helvetica", 10), fg="#888", bg="#1f1f1f")
credit_label.pack(side="bottom", pady=15)

root.mainloop()

