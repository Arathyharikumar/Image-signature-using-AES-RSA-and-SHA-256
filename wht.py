import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from PIL import Image
import os

# Function to hash an image using SHA-256
def hash_image(image_path):
    with open(image_path, 'rb') as image_file:
        image_data = image_file.read()
        return hashlib.sha256(image_data).hexdigest()

# Function to encrypt data using AES
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes  # Prepend IV for decryption

# Function to decrypt data using AES
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
    return decrypted_data

# Function to sign a hash using RSA
def sign_hash(hash_value, private_key):
    key = RSA.import_key(private_key)
    # Create a SHA-256 hash object
    hash_object = SHA256.new(hash_value.encode())
    signature = pkcs1_15.new(key).sign(hash_object)
    return signature

# Function to verify a signature using RSA
def verify_signature(hash_value, signature, public_key):
    key = RSA.import_key(public_key)
    hash_object = SHA256.new(hash_value.encode())
    try:
        pkcs1_15.new(key).verify(hash_object, signature)
        return True
    except (ValueError, TypeError):
        return False

# Main execution
if __name__ == "__main__":
    # Load your image
    image_path = r"C:\Users\hknna\OneDrive\Pictures\peakpx.jpg"
    
    # Hash the image
    image_hash = hash_image(image_path)
    print(f"Image Hash: {image_hash}")

    # Generate AES key (16 bytes for AES-128)
    aes_key = os.urandom(16)
    
    # Encrypt the image data
    with open(image_path, 'rb') as img_file:
        image_data = img_file.read()
    encrypted_data = encrypt_data(image_data, aes_key)
    
    # Generate RSA keys (for demo purposes, use small key size)
    rsa_key = RSA.generate(2048)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()

    # Sign the hash of the image
    signature = sign_hash(image_hash, private_key)
    
    # Verification
    is_verified = verify_signature(image_hash, signature, public_key)
    print(f"Signature Verified: {is_verified}")

    # Decrypt the image data to demonstrate
    decrypted_data = decrypt_data(encrypted_data, aes_key)
    with open("decrypted_image.jpg", 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    print("Image encrypted, signed, and decrypted successfully.")
