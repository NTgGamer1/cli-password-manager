import bcrypt
import utils.database as db

def check_if_setup():
    """
    Checks if the system already has a master password set up.
    
    Inputs: None
    Outputs:
        bool: True if a password exists, False otherwise.
    """
    # db.get_master_password_hash() returns None if no password exists.
    return db.get_master_password_hash() is not None

def hash_and_save_master_password(plaintext_password):
    """
    Uses bcrypt to securely hash a plain-text password and saves it to the DB.
    
    Inputs:
        plaintext_password (str): The raw string password user wants as their master.
    Outputs: None
    """
    # bcrypt expects raw bytes, so we encode our string first.
    password_bytes = plaintext_password.encode('utf-8')
    
    # bcrypt automatically generates a random, cryptographically secure salt,
    # then hashes the password along with that salt.
    # The salt is embedded into the returned 'hashed_bytes' string.
    hashed_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    
    # Convert back to a normal python string to store in the database easily.
    hashed_string = hashed_bytes.decode('utf-8')
    
    # Pass our newly hashed string over to database.py to actually save it!
    db.set_master_password(hashed_string)

def verify_master_password(plaintext_password):
    """
    Verifies if a typed-in password matches the stored hashed master password.
    
    Inputs:
        plaintext_password (str): The raw password the user just attempted to log in with.
    Outputs:
        bool: True if passwords match, False if they do not match or if none exists.
    """
    # Grab the true hash from the database.
    stored_hash_string = db.get_master_password_hash()
    
    if stored_hash_string is None:
        return False
        
    # bcrypt requires bytes, so we have to convert both our attempted password
    # and the stored hash string back into bytes.
    attempt_bytes = plaintext_password.encode('utf-8')
    stored_hash_bytes = stored_hash_string.encode('utf-8')
    
    # checkpw securely compares the attempt with the true hash without exposing the password.
    is_match = bcrypt.checkpw(attempt_bytes, stored_hash_bytes)
    
    return is_match
