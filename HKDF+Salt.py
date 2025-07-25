import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
import numpy as np

# --------------------------------
# BB84-Based Secret Passcode Generator
# --------------------------------
def generate_bb84_passcode(msg_hash, length=64):
    seed = int.from_bytes(SHA3_256.new(msg_hash).digest(), 'big')
    rng = np.random.default_rng(seed)

    bits = rng.integers(0, 2, length)
    sender_bases = rng.integers(0, 2, length)
    receiver_bases = rng.integers(0, 2, length)

    # Keep only bits where bases align
    aligned_bits = [bits[i] for i in range(length) if sender_bases[i] == receiver_bases[i]]
    if len(aligned_bits) < 16:
        raise ValueError("Not enough aligned bases for secure key!")
    return bytes(aligned_bits)

# --------------------------------
# AES-GCM Encryption / Decryption
# --------------------------------
def encrypt_aes_gcm(key, plaintext):
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv + ciphertext + tag

def decrypt_aes_gcm(key, data):
    iv = data[:12]
    ciphertext = data[12:-16]
    tag = data[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)

# --------------------------------
# HKDF Derivation
# --------------------------------
def derive_key(passcode, salt):
    return HKDF(passcode, 32, salt, SHA3_256)

# --------------------------------
# File Save/Load Helpers
# --------------------------------
def save_to_file(filepath, salt, msg_hash, ciphertext):
    with open(filepath, "wb") as f:
        f.write(salt + msg_hash + ciphertext)

def load_from_file(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
    salt = data[:16]
    msg_hash = data[16:48]
    ciphertext = data[48:]
    return salt, msg_hash, ciphertext

# --------------------------------
# Encrypt / Decrypt TEXT
# --------------------------------
def encrypt_message():
    msg = simpledialog.askstring("Encrypt", "Enter message to encrypt:")
    if not msg:
        return

    m_bytes = msg.encode()
    msg_hash = SHA3_256.new(m_bytes).digest()
    salt = get_random_bytes(16)
    passcode = generate_bb84_passcode(msg_hash)
    key = derive_key(passcode, salt)
    ciphertext = encrypt_aes_gcm(key, m_bytes)

    filepath = filedialog.asksaveasfilename(defaultextension=".qce", filetypes=[("QCE Files", "*.qce")])
    if filepath:
        save_to_file(filepath, salt, msg_hash, ciphertext)
        messagebox.showinfo("Success", f"Encrypted and saved to:\n{filepath}")

def decrypt_message():
    filepath = filedialog.askopenfilename(filetypes=[("QCE Files", "*.qce")])
    if not filepath:
        return

    try:
        salt, msg_hash, ciphertext = load_from_file(filepath)
        passcode = generate_bb84_passcode(msg_hash)
        key = derive_key(passcode, salt)
        plaintext = decrypt_aes_gcm(key, ciphertext)
        messagebox.showinfo("Decrypted Message", f"Message:\n\n{plaintext.decode()}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")

# --------------------------------
# Encrypt / Decrypt FILE
# --------------------------------
def encrypt_file():
    in_path = filedialog.askopenfilename(title="Select file to encrypt")
    if not in_path:
        return

    with open(in_path, "rb") as f:
        data = f.read()

    msg_hash = SHA3_256.new(data).digest()
    salt = get_random_bytes(16)
    passcode = generate_bb84_passcode(msg_hash)
    key = derive_key(passcode, salt)
    ciphertext = encrypt_aes_gcm(key, data)

    out_path = filedialog.asksaveasfilename(defaultextension=".qce", filetypes=[("QCE Files", "*.qce")])
    if out_path:
        save_to_file(out_path, salt, msg_hash, ciphertext)
        messagebox.showinfo("Success", f"File encrypted and saved to:\n{out_path}")

def decrypt_file():
    in_path = filedialog.askopenfilename(filetypes=[("QCE Files", "*.qce")])
    if not in_path:
        return

    try:
        salt, msg_hash, ciphertext = load_from_file(in_path)
        passcode = generate_bb84_passcode(msg_hash)
        key = derive_key(passcode, salt)
        plaintext = decrypt_aes_gcm(key, ciphertext)
        out_path = filedialog.asksaveasfilename(title="Save decrypted file as")
        if out_path:
            with open(out_path, "wb") as f:
                f.write(plaintext)
            messagebox.showinfo("Success", f"File decrypted and saved to:\n{out_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")

# --------------------------------
# Build GUI Window
# --------------------------------
root = tk.Tk()
root.title("Quantum BB84-Inspired Encryptor")
root.geometry("420x420")
root.configure(bg="#f0f0f0")

tk.Label(
    root, text="Quantum-Inspired BB84 Encryptor", font=("Helvetica", 16, "bold"), bg="#f0f0f0"
).pack(pady=20)

tk.Button(root, text="Encrypt Message", command=encrypt_message, bg="#4CAF50", fg="white", font=("Arial", 12), width=22).pack(pady=5)
tk.Button(root, text="Decrypt Message", command=decrypt_message, bg="#2196F3", fg="white", font=("Arial", 12), width=22).pack(pady=5)
tk.Button(root, text="Encrypt File", command=encrypt_file, bg="#4CAF50", fg="white", font=("Arial", 12), width=22).pack(pady=5)
tk.Button(root, text="Decrypt File", command=decrypt_file, bg="#2196F3", fg="white", font=("Arial", 12), width=22).pack(pady=5)

tk.Label(
    root,
    text="Encrypts/Decrypts with BB84-inspired passcode.\nStored .qce has salt + hash + ciphertext.",
    bg="#f0f0f0",
    font=("Arial", 10)
).pack(pady=20)

root.mainloop()
