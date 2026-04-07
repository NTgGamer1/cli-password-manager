import sys
import getpass
import utils.database as db
import utils.auth as auth
import utils.encryption as enc

def setup_master_password():
    """
    Guides the user through setting up their master password for the first time.
    
    Inputs: None
    Outputs:
        bytes: The derived encryption key ready to be passed around.
    """
    print("\n=== Welcome to your new CLI Password Manager! ===")
    print("It looks like this is your first time here.")
    
    while True:
        # getpass hides the typed characters so shoulder-surfers can't see the password!
        pwd = getpass.getpass("Create a Master Password: ")
        confirm = getpass.getpass("Confirm Master Password: ")
        
        if pwd == confirm:
            print("Encrypting and saving your master password...")
            auth.hash_and_save_master_password(pwd)
            print("Setup Complete! Do not forget this. There is NO recovery option.")
            break
        else:
            print("Passwords do not match. Let's try again.\n")
            
    # We return the encryption key derived from this master password so the session can begin!
    return enc.derive_key_from_password(pwd)

def login():
    """
    Prompts the user to log in and validates their master password.
    
    Inputs: None
    Outputs:
        bytes: The derived encryption key if successful, or None if failed.
    """
    print("\n=== CLI Password Manager ===")
    
    for attempt in range(3):
        pwd = getpass.getpass("Enter your Master Password: ")
        
        if auth.verify_master_password(pwd):
            print("Access Granted!")
            return enc.derive_key_from_password(pwd)
        else:
            print(f"Access Denied. {2 - attempt} attempts remaining.")
            
    print("Too many failed attempts. Exiting.")
    return None

def display_menu():
    """
    Prints the interactive menu options to the terminal.
    """
    print("\n--- Main Menu ---")
    print("1. Add a new password")
    print("2. View all saved passwords")
    print("3. Edit a password")
    print("4. Delete a password")
    print("5. Exit")
    print("-----------------")

def main():
    """
    The orchestrator function. It manages setup, login, and the continuous main loop.
    """
    # 1. Ensure the database file & tables actually exist before we do anything.
    db.init_db()
    
    # 2. Check if the user needs to set up a master password, or just log in.
    if not auth.check_if_setup():
        session_key = setup_master_password()
    else:
        session_key = login()
        if session_key is None:
            # Login failed. sys.exit quits the python program immediately.
            sys.exit(1)
            
    # 3. Enter the main infinite loop of our CLI application.
    while True:
        display_menu()
        choice = input("Select an option (1-5): ").strip()
        
        if choice == '1':
            service = input("Enter the service (e.g., Google, Netflix): ").strip()
            username = input("Enter the username/email: ").strip()
            pwd = getpass.getpass("Enter the password for this service: ")
            
            # Encrypt the raw password into scrambled text BEFORE saving to the database.
            encrypted_pwd = enc.encrypt_password(session_key, pwd)
            db.add_password(service, username, encrypted_pwd)
            print(f"SUCCESS: Saved password for {service}.")
            
        elif choice == '2':
            # Grab all rows from the database.
            rows = db.get_all_passwords()
            if not rows:
                print("Your vault is currently empty.")
            else:
                print("\n--- Your Vault ---")
                # Each row is a tuple: (id, service, username, encrypted_password, created_at)
                for r in rows:
                    p_id, service, username, encrypted_hash, created_at = r
                    
                    # Decrypt the scramble text back into the real password we can read.
                    try:
                        decrypted_pwd = enc.decrypt_password(session_key, encrypted_hash)
                        print(f"[{p_id}] {service} | User: {username} | Pass: {decrypted_pwd}")
                    except Exception as e:
                        print(f"[{p_id}] {service} | User: {username} | Pass: [DECRYPTION FAILED]")
                        
        elif choice == '3':
            rows = db.get_all_passwords()
            if not rows:
                print("No passwords to edit.")
                continue
                
            p_id_input = input("Enter the ID number of the password to edit: ").strip()
            if not p_id_input.isdigit():
                print("Invalid ID.")
                continue
                
            p_id = int(p_id_input)
            
            service = input("Enter the new service name: ").strip()
            username = input("Enter the new username/email: ").strip()
            new_pwd = getpass.getpass("Enter the new password: ")
            
            enc_pwd = enc.encrypt_password(session_key, new_pwd)
            db.update_password(p_id, service, username, enc_pwd)
            print("SUCCESS: Password updated.")
            
        elif choice == '4':
            rows = db.get_all_passwords()
            if not rows:
                print("No passwords to delete.")
                continue
                
            p_id_input = input("Enter the ID number of the password to delete: ").strip()
            if not p_id_input.isdigit():
                print("Invalid ID.")
                continue
                
            db.delete_password(int(p_id_input))
            print("SUCCESS: Password deleted.")
            
        elif choice == '5':
            print("Exiting Password Manager. Stay safe!")
            break
            
        else:
            print("Invalid selection. Please enter a number from 1 to 5.")

# A Python convention meaning: "Only run the main() function if this core file is executed directly." 
if __name__ == "__main__":
    main()
