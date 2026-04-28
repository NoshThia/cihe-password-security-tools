from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


def get_cipher():
    key = current_app.config["VAULT_ENCRYPTION_KEY"]
    return Fernet(key)


def encrypt_password(plain_text_password):
    if not plain_text_password:
        return ""

    cipher = get_cipher()
    encrypted = cipher.encrypt(plain_text_password.encode("utf-8"))
    return encrypted.decode("utf-8")


def decrypt_password(encrypted_password):
    if not encrypted_password:
        return ""

    cipher = get_cipher()

    try:
        decrypted = cipher.decrypt(encrypted_password.encode("utf-8"))
        return decrypted.decode("utf-8")
    except InvalidToken:
        return "[DECRYPTION_FAILED]"