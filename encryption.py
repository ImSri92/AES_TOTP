from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import pyotp
import qrcode
import os

def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)

def generate_key():
    return get_random_bytes(32)

def save_key(key, filename):
    with open(filename, "wb") as f:
        f.write(key)

def load_key(filename):
    with open(filename, "rb") as f:
        return f.read()

def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return iv, ciphertext

def decrypt_data(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data.decode()

def caesar_decrypt(ciphertext, shift):
    decrypted_text = ""

    for char in ciphertext:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                decrypted_text += chr((ord(char) - ord('a') - shift_amount) % 26 + ord('a'))
            else:
                decrypted_text += chr((ord(char) - ord('A') - shift_amount) % 26 + ord('A'))
        else:
            decrypted_text += char

    return decrypted_text


def main():
    key_filename = "key.key"
    encrypted_filename = "encrypted_data.bin"

    # Generate a random key and save it
    key = generate_key()
    save_key(key, key_filename)

    # Load the key from file
    key = load_key(key_filename)

    # Generate a TOTP secret (you should store and reuse this secret in a real application)
    totp_secret = pyotp.random_base32()

    # Create a TOTP object using the secret
    totp = pyotp.TOTP(totp_secret)

    # Generate a QR code containing the TOTP provisioning URI
    provisioning_uri = totp.provisioning_uri("Test2@example.com", issuer_name="Siva AES Python")
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    # Save the QR code image to a file
    img = qr.make_image(fill_color="black", back_color="white")
    img.save("otp_qr.png")

    # Print the URL containing the OTP provisioning URI for the TOTP secret
    print("Add this URI to your OTP Authenticator app:")
    print(pyotp.totp.TOTP(totp_secret).provisioning_uri("sivatheja0000@gmail.com", issuer_name="AES_Python"))

    # Wait for the user to set up the OTP Authenticator app
    input("Press Enter after setting up the OTP Authenticator app...")

    # Verify the OTP entered by the user
    otp = input("Enter the OTP from your Authenticator app: ")

    if not verify_otp(totp_secret, otp):
        print("Invalid OTP. Access denied.")
        return

    # Encrypt the data
    txt_file_path = r'D:\SHU\Classes\Cryptography\AES_Python\input_data.txt'  # The path to your text file
    with open(txt_file_path, 'r') as f:
        caesar_ciphertext = f.read()

    # Decrypt the Caesar cipher text
    caesar_shift = 3  # Change this value to the actual shift used in the Caesar cipher
    decrypted_caesar_text = caesar_decrypt(caesar_ciphertext, caesar_shift)

    # Encrypt the decrypted Caesar cipher text using AES
    iv, ciphertext = encrypt_data(key, decrypted_caesar_text)

    # Save the encrypted data to a file
    with open(encrypted_filename, "wb") as f:
        f.write(iv + ciphertext)

    # Read the encrypted data from the file
    with open(encrypted_filename, "rb") as f:
        content = f.read()
        iv, ciphertext = content[:AES.block_size], content[AES.block_size:]

    # Decrypt the data
    decrypted_data = decrypt_data(key, iv, ciphertext)
    print("Decrypted data:", decrypted_data)

if __name__ == "__main__":
    main()
