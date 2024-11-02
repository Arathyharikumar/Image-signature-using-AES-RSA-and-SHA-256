import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os

# Function to hash an image using SHA-256
def hash_image(image_path):
    with open(image_path, 'rb') as image_file:
        image_data = image_file.read()
        return hashlib.sha256(image_data).hexdigest()

# Function to sign a hash using RSA
def sign_hash(hash_value, private_key):
    key = RSA.import_key(private_key)
    hash_object = SHA256.new(hash_value.encode())
    signature = pkcs1_15.new(key).sign(hash_object)
    return signature.hex()  # Returning signature as hex string

# Function to encrypt image data using AES
def encrypt_image(image_data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(image_data, AES.block_size))
    return cipher.iv + ct_bytes  # Prepend IV for decryption

# Function to decrypt image data using AES
def decrypt_image(encrypted_data, aes_key):
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
    return decrypted_data

# Function to open file dialog and select an image
def upload_image():
    file_path = filedialog.askopenfilename(title="Select an Image", filetypes=[("Image Files", "*.jpg;*.jpeg;*.png")])
    if file_path:
        image_hash = hash_image(file_path)
        rsa_key = RSA.generate(2048)
        private_key = rsa_key.export_key()
        signature = sign_hash(image_hash, private_key)

        # Encrypt the image
        with open(file_path, 'rb') as img_file:
            image_data = img_file.read()
        
        aes_key = os.urandom(16)  # Generate a random AES key
        encrypted_image = encrypt_image(image_data, aes_key)

        # Show the result
        messagebox.showinfo("Signature Generated", f"Image Hash: {image_hash}\nSignature: {signature}\nImage Encrypted.")

        # Save the decrypted image
        decrypted_data = decrypt_image(encrypted_image, aes_key)
        decrypted_image_path = filedialog.asksaveasfilename(defaultextension=".jpg", title="Save Decrypted Image", filetypes=[("Image Files", "*.jpg;*.jpeg;*.png")])
        if decrypted_image_path:
            with open(decrypted_image_path, 'wb') as dec_file:
                dec_file.write(decrypted_data)
            messagebox.showinfo("Image Saved", "Decrypted image saved successfully.")

# Setting up the GUI
app = tk.Tk()
app.title("Image Signature Application")
app.geometry("400x300")
app.configure(bg="#f0f0f0")

# Styling
style = ttk.Style()
style.configure("TButton", font=("Arial", 12), padding=10)
style.configure("TLabel", font=("Arial", 10), background="#f0f0f0")
style.configure("TFrame", background="#f0f0f0")

frame = ttk.Frame(app)
frame.pack(pady=20)

# Title label
title_label = ttk.Label(frame, text="Image Signature App", font=("Arial", 16), background="#f0f0f0")
title_label.pack(pady=10)

# Upload button
upload_btn = ttk.Button(frame, text="Upload Image", command=upload_image)
upload_btn.pack(pady=20)

# Footer label
footer_label = ttk.Label(frame, text="Select an image to sign", background="#f0f0f0")
footer_label.pack(pady=10)

app.mainloop()
