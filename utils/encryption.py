import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# In a true production environment, you would want a UNIQUE salt generated for every user
# and stored in the database next to their hashed password. 
# For our CLI learning tool, we'll use a constant random byte string as the salt.
# Think of SALT as a "secret spice" that makes brute-forcing your master password much harder.
STATIC_SALT = b"CLI_PASSWORD_MANAGER_STATIC_SECRET_SALT_123"

def derive_key_from_password(master_password):
    """
    Takes the plain-text master password of the user and derives a secure encryption key from it.
    It uses PBKDF2HMAC (Password-Based Key Derivation Function 2) to stretch the master password
    into a mathematically secure 32-byte key needed for Fernet encryption.
    
    Inputs:
        master_password (str): The plain text master password entered by the user.
    Outputs:
        bytes: A secure, base64-encoded URL-safe key derived from the password.
    """
    # First, let's establish our key stretcher (KDF - Key Derivation Function).
    # We use a secure hashing algorithm (SHA256) and iterate 480,000 times!
    # Iterating hundreds of thousands of times slows down hackers trying to guess passwords.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=STATIC_SALT,
        iterations=480000,
    )
    
    # KDF libraries usually expect bytes, not normal python strings, so we encode the string to bytes.
    password_bytes = master_password.encode("utf-8")
    
    # derive() churns our password and salt through those 480,000 rounds.
    derived_bytes = kdf.derive(password_bytes)
    
    # Fernet (our encryption tool) strictly requires a base64 encoded URL-safe string.
    # URL-safe just means it replaces + and / characters with - and _ so it works nicely as text anywhere.
    key = base64.urlsafe_b64encode(derived_bytes)
    
    return key

def encrypt_password(key, plaintext_password):
    """
    Encrypts a plain-text password using the derived master key.
    
    Inputs:
        key (bytes): The base64 URL-safe derived key from the master password.
        plaintext_password (str): The raw string password the user wants to save.
    Outputs:
        str: The encrypted, safe-to-save string representation of the password.
    """
    # Initialize the Fernet encryptor with our secure key.
    f = Fernet(key)
    
    # Fernet encrypts bytes, so we encode our normal text password into bytes first.
    pass_bytes = plaintext_password.encode("utf-8")
    
    # Actually perform the encryption! 
    # Fernet guarantees that a message encrypted using it cannot be manipulated or read without the key.
    encrypted_bytes = f.encrypt(pass_bytes)
    
    # Convert the bytes back into a standard Python string so SQLite can easily store it as TEXT.
    return encrypted_bytes.decode("utf-8")

def decrypt_password(key, encrypted_password):
    """
    Decrypts an encrypted password from the database back into plain text.
    
    Inputs:
        key (bytes): The base64 URL-safe derived key from the master password.
        encrypted_password (str): The encrypted string that was pulled from the database.
    Outputs:
        str: The original, plain-text password.
    """
    f = Fernet(key)
    
    # Convert the string from SQLite back into bytes so Fernet can read it.
    enc_bytes = encrypted_password.encode("utf-8")
    
    # Decrypt the bytes back into raw data.
    decrypted_bytes = f.decrypt(enc_bytes)
    
    # Finally, decode the bytes back into a human-readable Python string.
    return decrypted_bytes.decode("utf-8")
