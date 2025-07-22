import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import struct
import os

# --- PBKDF2 key derivation ---
SALT = b'\x00' * 16  # Demo salt — replace with random for production

def generate_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data_bytes, password):
    key = generate_key(password)
    f = Fernet(key)
    return f.encrypt(data_bytes)

def decrypt_data(encrypted_bytes, password):
    key = generate_key(password)
    f = Fernet(key)
    return f.decrypt(encrypted_bytes)

def to_bin(data_bytes):
    return ''.join([format(byte, '08b') for byte in data_bytes])

def encode(image_path, data_bytes, output_path):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    encoded = img.copy()
    w, h = img.size
    pixels = encoded.load()

    length = len(data_bytes)
    length_bytes = struct.pack(">I", length)
    full_data = length_bytes + data_bytes
    binary_data = to_bin(full_data)

    data_index = 0
    for y in range(h):
        for x in range(w):
            pixel = list(pixels[x, y])
            for n in range(3):
                if data_index < len(binary_data):
                    pixel[n] = pixel[n] & ~1 | int(binary_data[data_index])
                    data_index += 1
            pixels[x, y] = tuple(pixel)
            if data_index >= len(binary_data):
                break
        if data_index >= len(binary_data):
            break

    encoded.save(output_path)

def decode(image_path):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    pixels = img.load()
    w, h = img.size

    binary_data = ""
    for y in range(h):
        for x in range(w):
            pixel = pixels[x, y]
            for n in range(3):
                binary_data += str(pixel[n] & 1)

    length_bits = binary_data[:32]
    length = int(length_bits, 2)
    data_bits = binary_data[32:32 + (length * 8)]
    data_bytes = bytes([int(data_bits[i:i+8], 2) for i in range(0, len(data_bits), 8)])
    return data_bytes

# --- GUI handlers ---
def embed_text():
    message = input_text.get("1.0", tk.END).strip()
    if not message:
        messagebox.showerror("Error", "Message cannot be empty.")
        return

    password = simpledialog.askstring("Password", "Set a password:", show="*")
    if not password:
        messagebox.showerror("Error", "Password is required!")
        return

    image_path = filedialog.askopenfilename(
        title="Select image to embed into",
        filetypes=[("Image Files", "*.png *.bmp")]
    )
    if not image_path:
        return

    encrypted = encrypt_data(message.encode(), password)
    payload = b'TXT' + encrypted

    output_path = filedialog.asksaveasfilename(defaultextension=".png")
    if not output_path:
        return

    encode(image_path, payload, output_path)
    input_text.delete("1.0", tk.END)
    status_label.config(text="✅ Text embedded!", fg="green")
    messagebox.showinfo("Success", f"Text hidden in image:\n{output_path}")

def embed_file():
    file_path = filedialog.askopenfilename(
        title="Select file to embed",
        filetypes=[("All Files", "*.*")]
    )
    if not file_path:
        return

    password = simpledialog.askstring("Password", "Set a password:", show="*")
    if not password:
        messagebox.showerror("Error", "Password is required!")
        return

    image_path = filedialog.askopenfilename(
        title="Select image to embed into",
        filetypes=[("Image Files", "*.png *.bmp")]
    )
    if not image_path:
        return

    with open(file_path, "rb") as f:
        file_data = f.read()

    filename_bytes = os.path.basename(file_path).encode()
    filename_len = struct.pack(">H", len(filename_bytes))

    combined = filename_len + filename_bytes + file_data
    encrypted = encrypt_data(combined, password)
    payload = b'FIL' + encrypted

    output_path = filedialog.asksaveasfilename(defaultextension=".png")
    if not output_path:
        return

    encode(image_path, payload, output_path)
    status_label.config(text="✅ File embedded!", fg="green")
    messagebox.showinfo("Success", f"File hidden in image:\n{output_path}")

def extract_data():
    image_path = filedialog.askopenfilename(
        filetypes=[("Image Files", "*.png *.bmp")]
    )
    if not image_path:
        return

    raw_bytes = decode(image_path)

    if raw_bytes[:3] == b'TXT':
        encrypted = raw_bytes[3:]
        password = simpledialog.askstring("Password", "Enter password:", show="*")
        if not password:
            return
        try:
            decrypted = decrypt_data(encrypted, password).decode()
            input_text.delete("1.0", tk.END)
            input_text.insert(tk.END, decrypted)
            status_label.config(text="✅ Text extracted!", fg="green")
            messagebox.showinfo("Success", "Text shown in text box.")
        except Exception:
            status_label.config(text="❌ Wrong password!", fg="red")
            messagebox.showerror("Error", "Wrong password or corrupted image data.")

    elif raw_bytes[:3] == b'FIL':
        encrypted = raw_bytes[3:]
        password = simpledialog.askstring("Password", "Enter password:", show="*")
        if not password:
            return
        try:
            decrypted = decrypt_data(encrypted, password)
            filename_len = struct.unpack(">H", decrypted[:2])[0]
            filename = decrypted[2:2+filename_len].decode()
            file_content = decrypted[2+filename_len:]

            save_path = filedialog.asksaveasfilename(initialfile=f"extracted_{filename}")
            if not save_path:
                return
            with open(save_path, "wb") as f:
                f.write(file_content)
            status_label.config(text="✅ File extracted!", fg="green")
            messagebox.showinfo("Success", f"File saved:\n{save_path}")
        except Exception:
            status_label.config(text="❌ Wrong password!", fg="red")
            messagebox.showerror("Error", "Wrong password or corrupted image data.")
    else:
        status_label.config(text="❌ No valid hidden data found.", fg="red")
        messagebox.showerror("Error", "No recognizable hidden data found.")

# --- GUI ---
root = tk.Tk()
root.title("🗝️ Cyber Warrior Steganography Tool")
root.geometry("950x700")
root.configure(bg="#1f1f1f")
root.resizable(False, False)

label_title = tk.Label(root, text="Steganography Tool", font=("Arial", 26, "bold"), bg="#1f1f1f", fg="#00ff99")
label_title.pack(pady=(20, 5))

label_desc = tk.Label(root, text="Embed secret TEXT or ANY FILE inside PNG/BMP images with password protection.",
                      font=("Arial", 13), bg="#1f1f1f", fg="#cccccc")
label_desc.pack(pady=(0, 20))

text_frame = tk.Frame(root, bg="#1f1f1f")
text_frame.pack()

input_text = tk.Text(text_frame, height=18, width=110, wrap="word", bg="#262626", fg="#00ff99", insertbackground="#00ff99")
input_text.pack()

button_frame = tk.Frame(root, bg="#1f1f1f")
button_frame.pack(pady=30)

embed_text_btn = tk.Button(button_frame, text="Embed Text", command=embed_text,
                           width=20, height=2, bg="#4CAF50", fg="white", font=("Arial", 11, "bold"))
embed_text_btn.grid(row=0, column=0, padx=30)

embed_file_btn = tk.Button(button_frame, text="Embed File", command=embed_file,
                           width=20, height=2, bg="#FF9800", fg="white", font=("Arial", 11, "bold"))
embed_file_btn.grid(row=0, column=1, padx=30)

extract_btn = tk.Button(button_frame, text="Extract Data", command=extract_data,
                        width=20, height=2, bg="#2196F3", fg="white", font=("Arial", 11, "bold"))
extract_btn.grid(row=0, column=2, padx=30)

status_label = tk.Label(root, text="", font=("Arial", 12), bg="#1f1f1f", fg="#00ff99")
status_label.pack(pady=(10, 20))

credit_label = tk.Label(root, text="🔒 Made by Cyber Warrior", font=("Arial", 11, "italic"),
                        bg="#1f1f1f", fg="#888")
credit_label.pack(side="bottom", pady=15)

root.mainloop()

