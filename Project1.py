from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

def generate_key():
    return Fernet.generate_key()

def save_key(key, filename):
    with open(filename, 'wb') as key_file:
        key_file.write(key)

def load_key(filename):
    with open(filename, 'rb') as key_file:
        return key_file.read()

def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

def generate_new_key():
    key = generate_key()
    save_key(key, 'secret.key')
    messagebox.showinfo("Key Generated", "New key has been generated and saved as 'secret.key'")

def encrypt_text():
    key = load_key('secret.key')
    message = message_entry.get("1.0", tk.END).strip()
    if message:
        encrypted_message = encrypt_message(message, key)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, encrypted_message.decode())
    else:
        messagebox.showwarning("No Data", "No text to encrypt.")

def decrypt_text():
    key = load_key('secret.key')
    encrypted_message = message_entry.get("1.0", tk.END).strip()
    try:
        encrypted_message_bytes = encrypted_message.encode()
        decrypted_message = decrypt_message(encrypted_message_bytes, key)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, decrypted_message)
    except Exception as e:
        messagebox.showerror("Decryption Error", f"Failed to decrypt message: {str(e)}")

def save_encrypted_message():
    encrypted_message = result_text.get("1.0", tk.END).strip()
    if encrypted_message:
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if filename:
            with open(filename, 'w') as file:
                file.write(encrypted_message)
            messagebox.showinfo("Saved", f"Encrypted message saved to {filename}")
    else:
        messagebox.showwarning("No Data", "No encrypted message to save.")

def load_encrypted_message():
    filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filename:
        with open(filename, 'r') as file:
            encrypted_message = file.read()
        message_entry.delete("1.0", tk.END)
        message_entry.insert(tk.END, encrypted_message)
    else:
        messagebox.showwarning("No File", "No file selected.")

app = tk.Tk()
app.title("Encryption/Decryption Tool")

app.configure(bg='#f0f0f0')
title_label = tk.Label(app, text="Encryption/Decryption Tool", font=('Arial', 16, 'bold'), bg='#f0f0f0')
title_label.pack(pady=10)

frame = tk.Frame(app, bg='#ffffff', padx=10, pady=10)
frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

tk.Label(frame, text="Enter text:", font=('Arial', 12), bg='#ffffff').pack()
message_entry = scrolledtext.ScrolledText(frame, width=40, height=10, wrap=tk.WORD)
message_entry.pack(pady=5)

button_frame = tk.Frame(frame, bg='#ffffff')
button_frame.pack(pady=10)

tk.Button(button_frame, text="Generate New Key", command=generate_new_key, bg='#4CAF50', fg='white').pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Encrypt", command=encrypt_text, bg='#2196F3', fg='white').pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Decrypt", command=decrypt_text, bg='#FF5722', fg='white').pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Save Encrypted Message", command=save_encrypted_message, bg='#FFC107', fg='black').pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Load Encrypted Message", command=load_encrypted_message, bg='#9E9E9E', fg='white').pack(side=tk.LEFT, padx=5)

tk.Label(frame, text="Result:", font=('Arial', 12), bg='#ffffff').pack()
result_text = scrolledtext.ScrolledText(frame, width=40, height=10, wrap=tk.WORD)
result_text.pack(pady=5)

app.mainloop()
