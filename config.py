import os
from cryptography.fernet import Fernet


BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def get_vault_key():
    key = os.environ.get("VAULT_ENCRYPTION_KEY")

    if key:
        return key.encode()

    key_file = os.path.join(BASE_DIR, "vault.key")

    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()

    new_key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(new_key)

    return new_key


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "psms-secret-key-change-this-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'psms.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    BLACKLIST_FILE = os.path.join(BASE_DIR, "data", "common_passwords.txt")
    DEFAULT_ADMIN_USERNAME = "admin"
    DEFAULT_ADMIN_PASSWORD = "Admin@1234"

    VAULT_ENCRYPTION_KEY = get_vault_key()

    # Gemini / LLM settings
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    LLM_ENABLED = bool(GEMINI_API_KEY)

    # Free-friendly Gemini model
    LLM_MODEL = os.environ.get("LLM_MODEL", "gemini-2.5-flash")