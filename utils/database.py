import sqlite3
import os

# We need to determine the path to our database file relative to THIS script.
# __file__ is a special variable in Python that contains the path to the current file.
# os.path.dirname(__file__) gets the directory containing this script (the 'utils' folder).
# We then use os.path.join to go up one folder ('..'), then into 'data', and name the file 'passwords.db'.
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "passwords.db")

def init_db():
    """
    Initializes the SQLite database. It creates the necessary tables if they don't already exist.
    It also ensures the directory for the database exists.
    
    Inputs: None
    Outputs: None
    """
    # First, make sure the directory where we want to save our database actually exists.
    # os.path.dirname gets the folder part of our DB_PATH.
    # os.makedirs creates the folder(s). exist_ok=True means it won't crash if the folder is already there.
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    # Establish a connection to our database file.
    # If 'passwords.db' doesn't exist, sqlite3 will create it automatically.
    conn = sqlite3.connect(DB_PATH)
    
    # We use a cursor to send SQL commands to our database. Think of it as a messenger.
    cursor = conn.cursor()
    
    # Create the master_password table.
    # We only need one master password, but setting an 'id' as PRIMARY KEY is good practice.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS master_password (
            id INTEGER PRIMARY KEY,
            hashed_password TEXT NOT NULL
        )
    ''')
    
    # Create the passwords table to store the different service logins.
    # DEFAULT CURRENT_TIMESTAMP automatically fills in the time when a new row is added.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Commit saves all the changes we just made to the database.
    conn.commit()
    
    # Always close the connection when you're done to free up resources!
    conn.close()

def set_master_password(hashed):
    """
    Saves the hashed master password into the database. If one already exists, it updates it.
    
    Inputs: 
        hashed (str): The cryptographic hash of the user's master password.
    Outputs: None
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # First, let's clear out the table just in case there's an old master password.
    # We only want one master password in the system at a time.
    cursor.execute('DELETE FROM master_password')
    
    # Now, insert the new hashed password.
    # We use a question mark (?) as a placeholder and provide the value in a tuple (hashed,).
    # This prevents SQL Injection attacks, a common security vulnerability.
    cursor.execute('INSERT INTO master_password (id, hashed_password) VALUES (1, ?)', (hashed,))
    
    conn.commit()
    conn.close()

def get_master_password_hash():
    """
    Retrieves the saved master password hash from the database.
    
    Inputs: None
    Outputs:
        str: The stored password hash as a string, or None if no master password is set.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Try to fetch the one and only master password. We look for 'id = 1'.
    cursor.execute('SELECT hashed_password FROM master_password WHERE id = 1')
    
    # fetchone() grabs the first matching row from the database.
    # Since we select only one column (hashed_password), the result is a tuple like ('my_hash_string',).
    result = cursor.fetchone()
    
    conn.close()
    
    # If result is None, it means the database is empty (no master password set yet).
    if result is None:
        return None
        
    # The actual string is stored at index 0 of the tuple.
    return result[0]

def add_password(service, username, encrypted_password):
    """
    Adds a new password entry to the database.
    
    Inputs:
        service (str): The name of the website or app (e.g., 'Google', 'Netflix').
        username (str): The username or email for the account.
        encrypted_password (str): The password, already encrypted by the app for safety.
    Outputs: None
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Insert the new data using parameterized queries (the (?) placeholders).
    cursor.execute('''
        INSERT INTO passwords (service, username, encrypted_password)
        VALUES (?, ?, ?)
    ''', (service, username, encrypted_password))
    
    conn.commit()
    conn.close()

def get_all_passwords():
    """
    Retrieves all stored passwords from the database.
    
    Inputs: None
    Outputs:
        list of tuples: Each tuple represents a row with (id, service, username, encrypted_password, created_at).
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # SELECT * means 'fetch all columns' from the passwords table.
    cursor.execute('SELECT * FROM passwords')
    
    # fetchall() grabs all the rows that match our query and returns them as a list.
    rows = cursor.fetchall()
    
    conn.close()
    return rows

def update_password(id_val, service, username, encrypted_password):
    """
    Updates an existing password entry based on its ID.
    
    Inputs:
        id_val (int): The unique database ID of the password to update.
        service (str): The potentially new service name.
        username (str): The potentially new username.
        encrypted_password (str): The new encrypted password.
    Outputs: None
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Update sets specific columns to new values for the row WHERE the id matches.
    cursor.execute('''
        UPDATE passwords
        SET service = ?, username = ?, encrypted_password = ?
        WHERE id = ?
    ''', (service, username, encrypted_password, id_val))
    
    conn.commit()
    conn.close()

def delete_password(id_val):
    """
    Removes a password entry from the database entirely.
    
    Inputs:
        id_val (int): The unique database ID of the password you want to delete.
    Outputs: None
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # DELETE FROM removes rows. WHERE id = ? ensures we only delete the specific one we are targeting.
    cursor.execute('DELETE FROM passwords WHERE id = ?', (id_val,))
    
    conn.commit()
    conn.close()

# This checks if this file is being run directly (e.g., 'python database.py').
# If it's being imported by another file (e.g., 'import database' in main.py), this block won't run.
if __name__ == "__main__":
    print("Initializing database...")
    init_db()
    print(f"Database successfully set up at: {os.path.abspath(DB_PATH)}")
