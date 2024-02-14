import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def pad(data):
    length = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([length] * length)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def encrypt(key, raw):
    raw = pad(raw)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(raw)

def decrypt(key, enc):
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(enc[AES.block_size:])
    try:
        return unpad(decrypted_data)
    except UnicodeDecodeError:
        return decrypted_data

def generate_key(key_size):
    if key_size == 128:
        return get_random_bytes(16)  # 128-bit key; 16 byte * 8
    elif key_size == 256:
        return get_random_bytes(32)  # 256-bit key; 32 byte * 8

def load_file():
    file_path = filedialog.askopenfilename(title="Select a hex file", filetypes=(("Hex files", "*.hex"), ("All files", "*.*")))
    if file_path:
        with open(file_path, 'rb') as f:
            hex_data = f.read()
            #print(f"this is your data: {hex_data}")
        return hex_data
    else:
        return None

def save_file(data):
    file_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=(("Encrypted files", "*.enc"), ("All files", "*.*")))
    if file_path:
        with open(file_path, 'wb') as f:
            f.write(data)
        messagebox.showinfo("Success", "The file was encrypted and saved successfully!")

# Function to save the key to a file
def save_key(key):
    with open("encryption_key.txt", "w") as f:
        f.write(key)

# Function to load the key from a file
def load_key():
    if os.path.exists("encryption_key.txt"):
        with open("encryption_key.txt", "r") as f:
            return f.read().strip()
    else:
        return None

def encrypt_file(key_size):
    hex_data = load_file()
    if hex_data is not None:
        key = generate_key(key_size)
        save_key(key.hex())
        encrypted_data = encrypt(key, hex_data)  # Pass the binary data directly
        save_file(encrypted_data)
        messagebox.showinfo("Encryption Key", f"Your encryption key is saved.\nSave this key to decrypt the file later.")

def decrypt_file(key_size):
    enc_data = load_file()
    if enc_data is not None:
        key_hex = simpledialog.askstring("Encryption Key", "Enter the encryption key :", show='*')
        saved_key = load_key()
        if key_hex == saved_key:
            key = bytes.fromhex(key_hex)
            if len(key) == 16 or len(key) == 32:
                decrypted_data = decrypt(key, enc_data)
                save_file(decrypted_data)  # Save decrypted data without encoding
                messagebox.showinfo("Success", "The file was decrypted and saved successfully!")
            else:
                messagebox.showerror("Error", "Invalid key length. Please enter a valid key.")
        else:
            messagebox.showerror("Error", "No key entered. Please enter a key.")

# Create the main window
root = tk.Tk()
root.title("AES Encryption & Decryption")

# Create a frame for the dropdown list and buttons
frame = tk.Frame(root)
frame.pack(padx=40 ,pady=40)

# Add a label for the dropdown list
label = tk.Label(frame, text="Select Key Size:")
label.grid(row=0, column=0, padx=10, pady=5)

# Add a dropdown list for selecting key size
key_size_var = tk.StringVar()
key_size_combobox = ttk.Combobox(frame, textvariable=key_size_var, values=["128", "256"])
key_size_combobox.grid(row=0, column=1, padx=10, pady=5)
key_size_combobox.current(0)  # Set default value to 128

# Add buttons for encryption and decryption
encrypt_button = tk.Button(frame, text="Encrypt a file", command=lambda: encrypt_file(int(key_size_var.get())), bg="yellow")
encrypt_button.grid(row=1, column=0, padx=10, pady=5)

decrypt_button = tk.Button(frame, text="Decrypt a file", command=lambda: decrypt_file(int(key_size_var.get())), bg="yellow")
decrypt_button.grid(row=1, column=1, padx=10, pady=5)

# Start the GUI event loop
root.mainloop()
